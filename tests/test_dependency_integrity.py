"""Synthetic checksum cases; fixtures live in caller-provided TMPDIR."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

_HELPER = Path(__file__).resolve().parents[1] / "scripts" / "verify_dependency.py"
_SPEC = importlib.util.spec_from_file_location("verify_dependency", _HELPER)
assert _SPEC is not None and _SPEC.loader is not None
integrity = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(integrity)


class DependencyIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dependency-integrity-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifact = self.root / "synthetic-dependency.jar"
        # ZIP-shaped bytes model the artifact that downstream code could unpack.
        with zipfile.ZipFile(self.artifact, "w") as archive:
            archive.writestr("synthetic-tool", b"synthetic fixture; never execute\n")
        self.baseline = self.artifact.read_bytes()
        self.expected = hashlib.sha256(self.baseline).hexdigest()

    def assert_hash_only(self, expected_status):
        with (
            mock.patch("zipfile.ZipFile", side_effect=AssertionError("must not extract")),
            mock.patch("subprocess.run", side_effect=AssertionError("must not execute")),
        ):
            result = integrity.verify(self.artifact, self.expected)
        self.assertEqual(result["status"], expected_status)
        self.assertEqual(set(result), {"status", "reason", "sha256", "filesize", "provenance"})
        return result

    def test_exact_bytes_pass_without_extracting_or_executing(self):
        result = self.assert_hash_only("verified")
        self.assertEqual(result["sha256"], self.expected)
        self.assertEqual(result["filesize"], len(self.baseline))
        self.assertEqual(result["provenance"], "predeclared-sha256-pin")
        self.assertEqual(integrity.verify(self.artifact, self.expected.upper())["status"], "verified")

    def test_one_byte_mutation_fails_without_extracting_or_executing(self):
        mutated = bytearray(self.baseline)
        mutated[len(mutated) // 2] ^= 1
        self.artifact.write_bytes(mutated)
        result = self.assert_hash_only("failed")
        self.assertEqual(result["reason"], "sha256_mismatch")
        self.assertNotEqual(result["sha256"], self.expected)
        self.assertEqual(result["provenance"], "unverified")

    def test_streaming_multiple_chunks_and_exact_size_limit(self):
        with mock.patch.object(integrity, "CHUNK_BYTES", 17):
            result = integrity.verify(self.artifact, self.expected, max_bytes=len(self.baseline))
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["sha256"], self.expected)

    def test_truncated_artifact_fails_without_extracting_or_executing(self):
        self.artifact.write_bytes(self.baseline[:-1])
        self.assertEqual(self.assert_hash_only("failed")["reason"], "sha256_mismatch")

    def test_missing_or_malformed_pin_fails_before_open(self):
        with mock.patch.object(integrity.os, "open", side_effect=AssertionError("must not open")):
            for expected in (None, "", "0" * 63, "0" * 65, "g" * 64, self.expected + "\n"):
                with self.subTest(expected=expected):
                    result = integrity.verify(self.artifact, expected)
                    self.assertEqual(result["reason"], "invalid_expected_sha256")
                    self.assertIsNone(result["sha256"])

    def test_size_limit_fails_before_read(self):
        with mock.patch.object(integrity.os, "read", side_effect=AssertionError("must not read")):
            result = integrity.verify(self.artifact, self.expected, max_bytes=len(self.baseline) - 1)
        self.assertEqual(result["reason"], "size_limit_exceeded")
        for limit in (0, -1, True, "1"):
            self.assertEqual(
                integrity.verify(self.artifact, self.expected, max_bytes=limit)["reason"],
                "invalid_size_limit",
            )

    def test_file_growth_is_bounded_and_fails(self):
        original_read = integrity.os.read
        calls = 0

        def grow_then_read(descriptor, size):
            nonlocal calls
            calls += 1
            if calls == 1:
                with self.artifact.open("ab") as artifact:
                    artifact.write(b"extra bytes after precheck")
            return original_read(descriptor, size)

        with mock.patch.object(integrity.os, "read", side_effect=grow_then_read):
            result = integrity.verify(self.artifact, self.expected, max_bytes=len(self.baseline))
        self.assertEqual(result["reason"], "size_limit_exceeded")
        self.assertEqual(result["filesize"], len(self.baseline) + 1)

    def test_changed_file_during_hash_fails(self):
        original_read = integrity.os.read
        changed = False

        def change_then_read(descriptor, size):
            nonlocal changed
            if not changed:
                changed = True
                with self.artifact.open("ab") as artifact:
                    artifact.write(b"changed")
            return original_read(descriptor, size)

        with mock.patch.object(integrity.os, "read", side_effect=change_then_read):
            self.assertEqual(integrity.verify(self.artifact, self.expected)["reason"], "artifact_changed")

    def test_nonregular_symlink_missing_and_empty_fail_safely(self):
        link = self.root / "synthetic-link"
        link.symlink_to(self.artifact)
        pipe = self.root / "synthetic-pipe"
        os.mkfifo(pipe)
        empty = self.root / "synthetic-empty"
        empty.write_bytes(b"")
        self.assertEqual(integrity.verify(link, self.expected)["reason"], "artifact_unreadable")
        self.assertEqual(integrity.verify(pipe, self.expected)["reason"], "not_regular_file")
        self.assertEqual(
            integrity.verify(self.root / "absent", self.expected)["reason"], "artifact_unreadable"
        )
        self.assertEqual(integrity.verify(empty, hashlib.sha256(b"").hexdigest())["reason"], "empty_artifact")

    def test_path_replacement_during_hash_fails(self):
        replacement = self.root / "synthetic-replacement.jar"
        replacement.write_bytes(self.baseline)
        original_read = integrity.os.read
        replaced = False

        def replace_then_read(descriptor, size):
            nonlocal replaced
            if not replaced:
                replaced = True
                replacement.replace(self.artifact)
            return original_read(descriptor, size)

        with mock.patch.object(integrity.os, "read", side_effect=replace_then_read):
            self.assertEqual(integrity.verify(self.artifact, self.expected)["reason"], "artifact_changed")

    def test_cli_returns_safe_json_and_nonzero_on_mismatch(self):
        self.artifact.write_bytes(self.baseline[:-1])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = integrity.main([str(self.artifact), "--expected-sha256", self.expected])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "sha256_mismatch")
        self.assertNotIn(str(self.artifact), output.getvalue())

    def test_cli_missing_pin_and_invalid_limit_are_safe_failures(self):
        for args in (
            [str(self.artifact)],
            [str(self.artifact), "--expected-sha256", self.expected, "--max-bytes", "invalid"],
        ):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(integrity.main(args), 1)
            self.assertEqual(json.loads(output.getvalue())["reason"], "invalid_arguments")
            self.assertNotIn(str(self.artifact), output.getvalue())


def test_workflow_pin_matches_published_checksums_and_guards_execution():
    root = Path(__file__).resolve().parents[1]
    provenance = json.loads((root / "docs/aapt2-integrity.json").read_text())
    workflow = yaml.load(
        (root / ".github/workflows/bundletool-validation.yml").read_text(), Loader=yaml.BaseLoader
    )
    job = workflow["jobs"]["official-fresh-splits"]
    expected = job["env"]["APSA_AAPT2_JAR_SHA256"]
    assert expected == provenance["observed_sha256"]
    assert provenance["pin_basis"] == "upstream-published-sha256"
    assert provenance["vendor_signature_verified"] is False
    assert len(provenance["independent_downloads"]) == 2
    for sidecar in provenance["upstream_checksums"]:
        assert sidecar["http_status"] == 200
        assert sidecar["source_url"] == provenance["artifact_url"] + "." + sidecar["algorithm"]
        assert all(
            observation[sidecar["algorithm"]] == sidecar["digest"]
            for observation in provenance["independent_downloads"]
        )
    assert "if" not in job
    download = next(step["run"] for step in job["steps"] if "Download pinned" in step.get("name", ""))
    assert download.index("scripts/verify_dependency.py") < download.index("unzip -q")
    assert download.index("APSA_DEPENDENCY_MUTATION=") < download.index("unzip -q")
    assert download.index("unzip -q") < download.index("chmod +x")
    assert '--expected-sha256 "$APSA_AAPT2_JAR_SHA256"' in download
    assert 'observation["reason"] != "sha256_mismatch"' in download
    execute = next(step["run"] for step in job["steps"] if "Execute real build" in step.get("name", ""))
    assert '--aapt2-jar "$RUNNER_TEMP/apsa-bundletool-tools/aapt2.jar"' in execute
    assert '--aapt2-jar-sha256 "$APSA_AAPT2_JAR_SHA256"' in execute
    watched = set(workflow["on"]["push"]["paths"])
    assert {
        "scripts/verify_dependency.py",
        "tests/test_dependency_integrity.py",
        "docs/DEPENDENCY_INTEGRITY.md",
        "docs/aapt2-integrity.json",
    } <= watched


if __name__ == "__main__":
    unittest.main()

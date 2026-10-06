"""Collect installed distribution metadata and unmodified bundled license files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def selected_packages(requirements: Path | None) -> set[str] | None:
    if requirements is None:
        return None
    selected = set()
    for line in requirements.read_text().splitlines():
        if not line or line[0].isspace() or line.startswith(("#", "--")):
            continue
        requirement = Requirement(line.removesuffix(" \\"))
        if requirement.marker is None or requirement.marker.evaluate():
            selected.add(canonicalize_name(requirement.name))
    return selected


def collect(output: Path, requirements: Path | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    selected = selected_packages(requirements)
    distributions = sorted(
        metadata.distributions(), key=lambda dist: canonicalize_name(dist.metadata["Name"])
    )
    included = [
        dist
        for dist in distributions
        if selected is None or canonicalize_name(dist.metadata["Name"]) in selected
    ]
    installed = {canonicalize_name(dist.metadata["Name"]): dist for dist in included}
    missing = sorted((selected or set()) - set(installed))
    if missing:
        raise ValueError(f"Missing installed metadata for locked dependencies: {', '.join(missing)}")
    records = []
    components = []
    dependencies = []
    for dist in included:
        name, version = dist.metadata["Name"], dist.version
        normalized = canonicalize_name(name)
        reference = f"pkg:pypi/{normalized}@{version}"
        license_files = []
        for entry in dist.files or []:
            basename = Path(str(entry)).name.upper()
            if basename not in {
                "LICENSE",
                "LICENSE.TXT",
                "LICENSE.MD",
                "LICENCE",
                "LICENCE.TXT",
                "COPYING",
                "COPYING.TXT",
                "NOTICE",
                "NOTICE.TXT",
                "AUTHORS",
            } and ".dist-info/licenses/" not in str(entry):
                continue
            original = Path(str(dist.locate_file(entry)))
            if not original.is_file() or original.is_symlink():
                continue
            if original.stat().st_size > 4 * 1024 * 1024:
                raise ValueError(f"Bundled license file exceeds the attribution budget: {name}/{basename}")
            relative = (
                Path("licenses") / f"{normalized}-{version}" / re.sub(r"[^A-Za-z0-9_.-]", "_", str(entry))
            )
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
            raw = target.read_bytes()
            license_files.append(
                {
                    "source_distribution_path": str(entry),
                    "bundle_path": relative.as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        expression = next(iter(dist.metadata.get_all("License-Expression", [])), None)
        declared = next(iter(dist.metadata.get_all("License", [])), None)
        classifiers = [
            value for value in dist.metadata.get_all("Classifier", []) if value.startswith("License ::")
        ]
        record = {
            "name": name,
            "version": version,
            "license_expression": expression,
            "metadata_license": declared,
            "license_classifiers": classifiers,
            "declared_license_files": dist.metadata.get_all("License-File", []),
            "license_files": license_files,
            "project_urls": dist.metadata.get_all("Project-URL", []),
            "attribution_state": "files-copied"
            if license_files
            else "metadata-only"
            if expression or declared or classifiers
            else "not-declared",
        }
        records.append(record)
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "purl": reference,
            "bom-ref": reference,
        }
        if expression:
            component["licenses"] = [{"expression": expression}]
        elif declared and len(declared) < 200 and "\n" not in declared:
            component["licenses"] = [{"license": {"name": declared}}]
        components.append(component)
        references = []
        for text in dist.requires or []:
            requirement = Requirement(text)
            dep_name = canonicalize_name(requirement.name)
            if dep_name in installed and (requirement.marker is None or requirement.marker.evaluate()):
                references.append(f"pkg:pypi/{dep_name}@{installed[dep_name].version}")
        dependencies.append({"ref": reference, "dependsOn": sorted(set(references))})
    app = metadata.distribution("apsa")
    app_ref = f"pkg:pypi/apsa@{app.version}"
    app_deps = []
    for text in app.requires or []:
        requirement = Requirement(text)
        dep_name = canonicalize_name(requirement.name)
        if dep_name in installed and (requirement.marker is None or requirement.marker.evaluate()):
            app_deps.append(f"pkg:pypi/{dep_name}@{installed[dep_name].version}")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "apsa",
                "version": app.version,
                "bom-ref": app_ref,
                "properties": [
                    {
                        "name": "inventory-scope",
                        "value": "Installed Python runtime distributions; excludes OS, SDK/device tools, and audited applications.",
                    }
                ],
            }
        },
        "components": components,
        "dependencies": [{"ref": app_ref, "dependsOn": sorted(set(app_deps))}, *dependencies],
    }
    notices = [
        "# Third-party notices",
        "",
        "이 목록은 잠긴 Python 런타임 의존성의 실제 설치 메타데이터와 배포본에 포함된 라이선스 파일에서 생성했습니다.",
        "라이선스 이름, 표현식, 저작권을 추측하거나 자체 제품의 라이선스를 지정하지 않습니다.",
        "`dependency-licenses.json`에 원래 선언을 보존하며 `licenses/`에 발견한 원문 파일을 그대로 복사합니다.",
        "파일 미포함 또는 선언 누락은 별도 표시합니다. 이 자료는 라이선스 의무의 법률적 판단을 대신하지 않습니다.",
        "",
        "| 의존성 | 버전 | 메타데이터 선언 | 수집 상태 |",
        "| --- | --- | --- | --- |",
    ]
    for record in records:
        declaration = (
            record["license_expression"]
            or record["metadata_license"]
            or "; ".join(record["license_classifiers"])
            or "선언 없음"
        )
        declaration = declaration.replace("|", "\\|").replace("\n", " ")
        if len(declaration) > 200:
            declaration = declaration[:200] + " (원문은 JSON 참조)"
        notices.append(
            f"| {record['name']} | {record['version']} | {declaration} | {record['attribution_state']} |"
        )
    (output / "dependency-licenses.json").write_text(
        json.dumps(records, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    )
    (output / "dependency-sbom.cdx.json").write_text(
        json.dumps(sbom, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    )
    (output / "THIRD_PARTY_NOTICES.md").write_text("\n".join(notices) + "\n")
    return {
        "distributions": len(records),
        "license_files": sum(len(record["license_files"]) for record in records),
        "metadata_only": [
            record["name"] for record in records if record["attribution_state"] == "metadata-only"
        ],
        "not_declared": [
            record["name"] for record in records if record["attribution_state"] == "not-declared"
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--requirements", type=Path)
    args = parser.parse_args()
    print(json.dumps(collect(args.out, args.requirements), sort_keys=True))


if __name__ == "__main__":
    main()

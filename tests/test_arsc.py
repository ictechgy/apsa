import unittest

from quaygate.arsc import parse_resource_names
from tests.helpers import build_arsc

TYPES = [("xml", ["network_security_config", "file_paths"]), ("string", ["app_name"])]
PATHS = {"network_security_config": "res/qK.xml"}

EXPECTED = {
    (0x7F << 24) | (1 << 16) | 0: ("xml", "network_security_config", "res/qK.xml"),
    (0x7F << 24) | (1 << 16) | 1: ("xml", "file_paths", None),
    (0x7F << 24) | (2 << 16) | 0: ("string", "app_name", None),
}


class ArscTest(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(parse_resource_names(build_arsc(TYPES, paths=PATHS)), EXPECTED)

    def test_sparse_roundtrip(self):
        self.assertEqual(parse_resource_names(build_arsc(TYPES, sparse=True, paths=PATHS)), EXPECTED)

    def test_compact_entries(self):
        """aapt2 compact — key u16, flags=(type<<8)|0x08, data u32(bool)."""
        result = parse_resource_names(build_arsc(TYPES, compact=True,
                                                  bool_true_refs=("app_name",)))
        self.assertEqual(result[(0x7F << 24) | (2 << 16) | 0][1], "app_name")
        self.assertEqual(result[(0x7F << 24) | (2 << 16) | 0][2], "true")

    def test_bool_values_dense(self):
        result = parse_resource_names(build_arsc(
            [("bool", ["dbg"])], bool_false_refs=("dbg",)))
        self.assertEqual(result[(0x7F << 24) | (1 << 16) | 0][2], "false")

    def test_garbage_returns_empty(self):
        self.assertEqual(parse_resource_names(b"\x00" * 256), {})

    def test_not_a_table(self):
        self.assertEqual(parse_resource_names(b"PK\x03\x03not arsc"), {})

    def test_truncated_returns_partial_or_empty(self):
        data = build_arsc(TYPES)
        # 청크 중간에서 잘려도 예외 없이 부분 결과
        result = parse_resource_names(data[: len(data) // 2])
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()

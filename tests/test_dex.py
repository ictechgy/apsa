import unittest

from quaygate.dex import dex_strings
from tests.helpers import build_dex


class DexTest(unittest.TestCase):
    def test_roundtrip(self):
        strings = ["com.example.Klass", "https://example.com", "테스트", "AES/ECB/PKCS5Padding"]
        self.assertEqual(dex_strings(build_dex(strings)), strings)

    def test_long_string_multibyte_uleb(self):
        s = "x" * 200
        self.assertEqual(dex_strings(build_dex([s])), [s])

    def test_empty(self):
        self.assertEqual(dex_strings(build_dex([])), [])

    def test_rejects_non_dex(self):
        with self.assertRaises(ValueError):
            dex_strings(b"not a dex file at all")


if __name__ == "__main__":
    unittest.main()

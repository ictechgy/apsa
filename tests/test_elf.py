import unittest

from quaygate.elf import parse
from tests.helpers import build_elf64


class ElfTest(unittest.TestCase):
    def test_fully_hardened(self):
        h = parse(build_elf64())
        self.assertEqual((h["pie"], h["nx"], h["relro"], h["canary"]),
                         (True, True, "full", True))

    def test_execstack_disables_nx(self):
        h = parse(build_elf64(execstack=True))
        self.assertFalse(h["nx"])

    def test_partial_relro(self):
        h = parse(build_elf64(relro="partial"))
        self.assertEqual(h["relro"], "partial")

    def test_no_relro(self):
        h = parse(build_elf64(relro="none"))
        self.assertEqual(h["relro"], "none")

    def test_no_pie_no_canary(self):
        h = parse(build_elf64(pie=False, canary=False))
        self.assertFalse(h["pie"])
        self.assertFalse(h["canary"])

    def test_not_elf(self):
        self.assertIsNone(parse(b"\x00" * 256))

    def test_truncated_returns_something(self):
        h = parse(build_elf64()[:80])
        self.assertIsNotNone(h)  # 헤더는 읽힘 — 부분 결과 허용


if __name__ == "__main__":
    unittest.main()

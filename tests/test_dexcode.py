import unittest

from quaygate.dexcode import analyze_dex
from tests.helpers import build_code_dex


class DexCodeTest(unittest.TestCase):
    def test_weak_crypto_call_site(self):
        d = build_code_dex([("Lcom/t/A;", "m0", "Ljavax/crypto/Cipher;",
                             "getInstance", "AES/ECB/PKCS5Padding")])
        result = analyze_dex(d)
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(len(result["weak_crypto"]), 1)
        self.assertIn("com.t.A", result["weak_crypto"][0])
        self.assertIn("AES/ECB/PKCS5Padding", result["weak_crypto"][0])

    def test_strong_algo_not_flagged(self):
        d = build_code_dex([("Lcom/t/B;", "m", "Ljava/security/MessageDigest;",
                             "getInstance", "SHA-256")])
        result = analyze_dex(d)
        self.assertEqual(result["weak_crypto"], [])

    def test_webview_and_dynamic(self):
        d = build_code_dex([
            ("Lcom/t/C;", "m", "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", None),
            ("Lcom/t/D;", "m", "Ldalvik/system/DexClassLoader;", "<init>", None),
            ("Lcom/t/E;", "m", "Ljava/lang/Runtime;", "exec", "sh"),
        ])
        result = analyze_dex(d)
        self.assertEqual(result["scanned"], 3)
        self.assertTrue(any("setJavaScriptEnabled" in w for w in result["webview"]))
        self.assertTrue(any("DexClassLoader" in x for x in result["dynamic"]))
        self.assertTrue(any("Runtime.exec" in x for x in result["dynamic"]))

    def test_declaring_class_label(self):
        d = build_code_dex([("Lcom/example/App;", "m", "Ljava/security/MessageDigest;",
                             "getInstance", "MD5")])
        result = analyze_dex(d)
        self.assertIn("com.example.App", result["weak_crypto"][0])

    def test_garbage_returns_none(self):
        self.assertIsNone(analyze_dex(b"not a dex at all"))

    def test_strings_only_dex_scans_zero(self):
        from tests.helpers import build_dex

        result = analyze_dex(build_dex(["com.example.Klass", "AES/ECB"]))
        self.assertEqual(result["scanned"], 0)


class CmpPrecedingTest(unittest.TestCase):
    def test_cmp_long_does_not_desync(self):
        """cmp-long(0x31, 2유닛) 뒤의 invoke/const-string이 검출되는지(크기표 회귀)."""
        import struct

        from quaygate.dexcode import DexCode
        insns = [
            0x1231, 0x0200, 0x0000,   # cmp-long v2, v0, v1 (23x, 2유닛)
            (0 << 8) | 0x1A, 6,       # const-string v0, s#6("MD5")
            (1 << 12) | 0x71, 0, 0,   # invoke-static {v0}, m#0
        ]
        blob = b"\x00" * 8 + struct.pack("<HHHHII", 4, 0, 2, 0, 0, len(insns))
        blob += b"".join(struct.pack("<H", u) for u in insns)
        dx = DexCode.__new__(DexCode)
        dx.data = blob
        dx._scan_cache = {}
        dx.strings = [""] * 8
        dx.strings[6] = "MD5"
        calls, strings = dx.scan_code(8)
        self.assertEqual(calls, [0])
        self.assertEqual(strings, ["MD5"])


class PayloadSkipTest(unittest.TestCase):
    def test_payload_body_not_scanned_as_instructions(self):
        """fill-array-data 페이로드 본문을 명령으로 오스캔하지 않는지 검증."""
        import struct

        from quaygate.dexcode import DexCode
        real_mid = 0
        insns = [
            0x0026, 0x0008, 0x0000,        # fill-array-data v0, +8(점프 목표는 스캔과 무관)
            0x1071, real_mid, 0x0000,      # 진짜 invoke-static {v0}, m#0
            0x0300, 0x0002,                # 페이로드: ident=3, element_width=2
            0x0003, 0x0000,                # size(count)=3 → 데이터 3유닛
            0x0071, 0x0001, 0x7100,        # 데이터: 유사 invoke 패턴(오탐 유도)
        ]
        blob = b"\x00" * 8 + struct.pack("<HHHHII", 4, 0, 2, 0, 0, len(insns))
        blob += b"".join(struct.pack("<H", u) for u in insns)
        dx = DexCode.__new__(DexCode)
        dx.data = blob
        dx._scan_cache = {}
        calls, strings = dx.scan_code(8)
        self.assertEqual(calls, [real_mid])
        self.assertEqual(strings, [])


if __name__ == "__main__":
    unittest.main()

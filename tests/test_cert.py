import unittest

from quaygate.cert import analyze_v1_certificate


def make_runner(pkcs7_rc=0, x509_rc=0, x509_out="", pkcs7_out="", fail=False):
    def runner(args, data=None):
        if fail:
            return None
        if args[0] == "pkcs7":
            return (pkcs7_rc, pkcs7_out, "pkcs7 err" if pkcs7_rc else "")
        return (x509_rc, x509_out, "x509 err" if x509_rc else "")
    return runner


class CertTest(unittest.TestCase):
    def test_debug_certificate(self):
        runner = make_runner(x509_out="subject=CN = Android Debug, O = Android, C = US\n"
                                      "notAfter=Jul 29 12:00:00 2048 GMT\n")
        info = analyze_v1_certificate(b"\x30\x82", runner=runner)
        self.assertTrue(info["debug"])
        self.assertFalse(info["expired"])

    def test_release_certificate_passes(self):
        runner = make_runner(x509_out="subject=CN = team@example.com, O = Example\n"
                                      "notAfter=Jul 29 12:00:00 2048 GMT\n")
        info = analyze_v1_certificate(b"\x30\x82", runner=runner)
        self.assertFalse(info["debug"])
        self.assertFalse(info["expired"])
        self.assertIn("team@example.com", info["subject"])

    def test_expired_certificate(self):
        runner = make_runner(x509_out="subject=CN = old\n"
                                      "notAfter=Jul 29 12:00:00 2020 GMT\n")
        info = analyze_v1_certificate(b"\x30\x82", runner=runner)
        self.assertTrue(info["expired"])
        self.assertFalse(info["debug"])

    def test_slash_format_subject(self):
        runner = make_runner(x509_out="subject=/CN=Android Debug/O=Android/C=US\n")
        info = analyze_v1_certificate(b"\x30\x82", runner=runner)
        self.assertTrue(info["debug"])

    def test_openssl_failure_reported(self):
        info = analyze_v1_certificate(b"\x30\x82", runner=make_runner(pkcs7_rc=1))
        self.assertIn("error", info)

    def test_runner_unavailable(self):
        info = analyze_v1_certificate(b"\x30\x82", runner=make_runner(fail=True))
        self.assertIn("error", info)


if __name__ == "__main__":
    unittest.main()

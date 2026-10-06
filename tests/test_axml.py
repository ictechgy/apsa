import unittest

from quaygate.axml import AxmlError, parse_axml
from tests.helpers import _start_element, axml_document, build_axml


class AxmlDocumentTest(unittest.TestCase):
    def test_tree_roundtrip(self):
        tree = [
            ("manifest", {"package": "com.example", "versionName": "1.2.3"}, [
                ("uses-sdk", {"minSdkVersion": "24", "targetSdkVersion": "34"}, []),
                ("application", {"allowBackup": "false", "debuggable": "false"}, [
                    ("activity", {"name": "com.example.Main", "exported": "true"}, [
                        ("intent-filter", {}, [
                            ("action", {"name": "android.intent.action.MAIN"}, []),
                        ]),
                    ]),
                ]),
            ]),
        ]
        events = parse_axml(axml_document(tree))
        starts = [(n, a) for ev, n, a in events if ev == "start"]
        self.assertEqual(starts[0][0], "manifest")
        self.assertEqual(starts[0][1]["package"], "com.example")
        self.assertEqual(starts[0][1]["versionName"], "1.2.3")
        app = next(a for n, a in starts if n == "application")
        self.assertEqual(app["allowBackup"], "false")
        activity = next(a for n, a in starts if n == "activity")
        self.assertEqual(activity["exported"], "true")
        self.assertEqual(len([1 for ev, _, _ in events if ev == "end"]), 6)

    def test_utf16_pool(self):
        chunk = _start_element(0, [(0xFFFFFFFF, 1, 2, 0x03, 2)])
        data = build_axml(["노드", "속성", "값16"], [chunk], utf8=False)
        events = parse_axml(data)
        self.assertEqual(events[0][2], {"속성": "값16"})

    def test_boolean_attr(self):
        chunk = _start_element(0, [(0xFFFFFFFF, 1, 0xFFFFFFFF, 0x12, 1)])
        data = build_axml(["n", "flag"], [chunk])
        self.assertEqual(parse_axml(data)[0][2], {"flag": "true"})

    def test_rejects_non_axml(self):
        with self.assertRaises(AxmlError):
            parse_axml(b"PK\x03\x03 plain zip bytes")

    def test_malformed_attr_count_raises_axml_error(self):
        # 손상 APK: 속성 개수가 청크 크기와 맞지 않음 — struct.error 대신 AxmlError로 종료
        import struct as _s
        from tests.helpers import build_axml
        ext = _s.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, 100, 0, 0, 0)
        chunk = _s.pack("<HHIII", 0x0102, 16, 16 + 20, 1, 0xFFFFFFFF) + ext
        with self.assertRaises(AxmlError):
            parse_axml(build_axml(["n"], [chunk]))

    def test_rejects_short(self):
        with self.assertRaises(AxmlError):
            parse_axml(b"\x03\x00")

    def test_text_nodes(self):
        tree = [("network-security-config", {}, [
            ("domain-config", {}, [
                ("domain", {"includeSubdomains": "true"}, ["mirror.example.com"]),
                ("domain", {}, ["두번째도메인"]),
            ]),
        ])]
        events = parse_axml(axml_document(tree))
        texts = [v for ev, v, _ in events if ev == "text"]
        self.assertEqual(texts, ["mirror.example.com", "두번째도메인"])


if __name__ == "__main__":
    unittest.main()

import class UIKit.UIApplication
import class WebKit.WKWebView
import struct Foundation.URLRequest
import struct Foundation.URL
class OwnedBase {}
class Intake: OwnedBase {
    let reader: WKWebView
    init(reader: WKWebView) { self.reader = reader }
    @MainActor func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {
        guard link.scheme == "https", link.host == "guide.example.test" else { return false }
        reader.load(URLRequest(url: link))
        return true
    }
}

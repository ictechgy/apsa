class Intake: UIViewController {
    let reader = WKWebView()
    func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {
        guard link.scheme == "https", link.host == "guide.example.test" else { return false }
        reader.load(URLRequest(url: link))
        return true
    }
}

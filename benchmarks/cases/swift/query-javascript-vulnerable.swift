class Intake {
    var reader: WKWebView!
    func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {
        let components = URLComponents(url: link, resolvingAgainstBaseURL: false)
        let script = components?.queryItems?.first?.value
        reader.evaluateJavaScript(script!)
        return true
    }
}

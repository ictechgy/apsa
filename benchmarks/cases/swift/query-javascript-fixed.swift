class Intake {
    var reader: WKWebView!
    func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {
        let components = URLComponents(url: link, resolvingAgainstBaseURL: false)
        let requestedSection = components?.queryItems?.first?.value
        audit.record(requestedSection)
        reader.evaluateJavaScript("showHelpSection()")
        return true
    }
}

class Intake: UIViewController {
    let reader = WKWebView()
    func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {
        let destination = link
        reader.load(URLRequest(url: destination))
        return true
    }
}

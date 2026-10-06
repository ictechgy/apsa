class Help {
    let reader = WKWebView()
    func application(_ app: UIApplication, open link: URL, options: [String: Any]) -> Bool {
        let destination = URL(string: "https://guide.example.test")!
        do {
            let destination = link
            audit.record(destination)
        }
        reader.load(URLRequest(url: destination))
        return true
    }
}

class Help {
    let reader = WKWebView()
    func show() {
        // reader.load(URLRequest(url: link))
        let sample = "reader.evaluateJavaScript(input); link.host.hasPrefix(guide)"
        reader.load(URLRequest(url: URL(string: "https://guide.example.test")!))
    }
}

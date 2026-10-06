class Navigation {
    func webView(_ view: WKWebView, decidePolicyFor request: WKNavigationAction,
                 decision: @escaping (WKNavigationActionPolicy) -> Void) {
        let destination = request.request.url!
        if destination.scheme == "https" && destination.host == "guide.example.test" {
            decision(.allow)
        } else { decision(.cancel) }
    }
}

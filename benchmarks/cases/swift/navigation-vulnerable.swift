class Navigation {
    func webView(_ view: WKWebView, decidePolicyFor request: WKNavigationAction,
                 decision: @escaping (WKNavigationActionPolicy) -> Void) {
        if request.request.url!.host!.hasPrefix("guide.example.test") {
            decision(.allow)
        } else { decision(.cancel) }
    }
}

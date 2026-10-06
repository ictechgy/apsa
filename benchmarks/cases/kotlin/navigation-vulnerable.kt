class Navigation : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        if (request.url.host!!.contains("guide.example.test")) {
            return false
        }
        return true
    }
}

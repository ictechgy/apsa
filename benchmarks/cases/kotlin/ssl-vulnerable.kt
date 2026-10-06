class CertificateClient : WebViewClient() {
    override fun onReceivedSslError(view: WebView, response: SslErrorHandler, error: SslError) {
        response.proceed()
    }
}

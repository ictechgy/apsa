class CertificateClient extends WebViewClient {
    public void onReceivedSslError(WebView view, SslErrorHandler response, SslError error) {
        response.cancel();
    }
}

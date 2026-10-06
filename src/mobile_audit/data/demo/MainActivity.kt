// Intentionally vulnerable example. This file is analysis input, not an installable app.
class MainActivity {
    fun display(url: String, token: String) {
        val webView = WebView(context)
        if (url.contains("trusted.example")) webView.loadUrl(url)
        webView.addJavascriptInterface(AccountBridge(), "account")
        Log.d("Account", token)
        preferences.edit().putString("session", token).apply()
    }
    fun onReceivedSslError(handler: SslErrorHandler) {
        handler.proceed()
    }
}

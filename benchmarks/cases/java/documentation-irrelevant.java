class Documentation {
    WebView reader;
    void show() {
        // reader.loadUrl(getIntent().getDataString());
        String instructions = "SslErrorHandler handler; handler.proceed(); reader.addJavascriptInterface(...)";
        String sample = "reader.loadUrl(getIntent().getDataString())";
        reader.loadUrl("https://guide.example.test");
    }
}

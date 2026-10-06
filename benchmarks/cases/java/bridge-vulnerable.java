class Intake {
    WebView reader;
    void open(Intent event) {
        reader.getSettings().setJavaScriptEnabled(true);
        reader.addJavascriptInterface(new HelpBridge(), "support");
        reader.loadUrl(event.getDataString());
    }
}

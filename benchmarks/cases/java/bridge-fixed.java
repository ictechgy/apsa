class Intake {
    WebView reader;
    void open(Intent event) {
        reader.getSettings().setJavaScriptEnabled(true);
        reader.addJavascriptInterface(new HelpBridge(), "support");
        reader.removeJavascriptInterface("support");
        Uri destination = event.getData();
        if (destination.getScheme().equals("https") && destination.getHost().equals("guide.example.test")) {
            reader.loadUrl(destination.toString());
        }
    }
}

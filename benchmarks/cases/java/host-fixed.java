class Intake {
    WebView reader;
    void open(Intent event) {
        Uri parsed = event.getData();
        if (parsed.getScheme().equals("https") && parsed.getHost().endsWith(".guide.example.test")) {
            reader.loadUrl(parsed.toString());
        }
    }
}

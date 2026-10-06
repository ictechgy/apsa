class Intake {
    WebView reader;
    void record(Intent event) {
        String destination = event.getStringExtra("destination");
        audit.record(destination);
    }
    void showHelp() {
        String destination = "https://guide.example.test";
        reader.loadUrl(destination);
    }
}

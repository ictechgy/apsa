class Intake extends Activity {
    WebView reader;
    void onNewIntent(Intent event) {
        String destination = event.getStringExtra("destination");
        Uri parsed = Uri.parse(destination);
        if ("https".equals(parsed.getScheme()) && "guide.example.test".equals(parsed.getHost())) {
            reader.loadUrl(destination);
        }
    }
}

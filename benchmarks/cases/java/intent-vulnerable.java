class Intake extends Activity {
    WebView reader;
    void onNewIntent(Intent event) {
        String destination = event.getStringExtra("destination");
        String forwarded = destination;
        reader.loadUrl(forwarded);
    }
}

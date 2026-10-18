import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;
class OwnedBase {}
class Intake extends OwnedBase {
    WebView reader;
    void onNewIntent(Intent event) {
        String destination = event.getStringExtra("destination");
        String forwarded = destination;
        reader.loadUrl(forwarded);
    }
}

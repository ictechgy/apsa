package audit.fixture;

import android.content.SharedPreferences;
import android.net.http.SslError;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

// Deliberately unsafe calls for bytecode ground truth, never installed/run.
public final class Calls extends WebViewClient {
    @Override public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed();
    }
    public static void configure(WebView view, Object bridge) {
        view.getSettings().setAllowUniversalAccessFromFileURLs(true);
        view.getSettings().setAllowFileAccessFromFileURLs(true);
        view.addJavascriptInterface(bridge, "FixtureBridge");
        WebView.setWebContentsDebuggingEnabled(true);
    }
    public static void store(SharedPreferences preferences, String token) {
        preferences.edit().putString("access_token", token).apply();
    }
    public static void log(SharedPreferences preferences) {
        String token = preferences.getString("access_token", "");
        Log.d("fixture", token);
    }
}

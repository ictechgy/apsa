package audit.fixture;

import android.content.SharedPreferences;
import android.net.http.SslError;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;

// Negative cases contain the same API names and token-like text as data.
public final class Calls extends WebViewClient {
    @Override public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.cancel();
    }
    public static void configure(WebView view) {
        view.getSettings().setAllowUniversalAccessFromFileURLs(false);
        view.getSettings().setAllowFileAccessFromFileURLs(false);
        WebView.setWebContentsDebuggingEnabled(false);
        Log.d("fixture", "access_token");
        Log.d("fixture", "Landroid/webkit/SslErrorHandler;->proceed()V");
        Log.d("fixture", "addJavascriptInterface");
    }
    public static void store(SharedPreferences preferences) {
        preferences.edit().putString("theme", "dark").apply();
    }
    public static void log(SharedPreferences preferences) {
        String theme = preferences.getString("theme", "");
        Log.d("fixture", theme);
    }
    public static void overwrite(WebView view) {
        boolean enabled = true;
        enabled = false;
        view.getSettings().setAllowUniversalAccessFromFileURLs(enabled);
    }
    public static void branch(WebView view, boolean choice) {
        boolean enabled = true;
        if (choice) enabled = false;
        view.getSettings().setAllowUniversalAccessFromFileURLs(enabled);
    }
}

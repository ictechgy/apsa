package audit.fixture.runtime;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.widget.TextView;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/** An owned test app with intentionally vulnerable and fixed modes. Never ship this fixture. */
public final class MainActivity extends Activity {
    private static final String ACCOUNT_A = "mobile-audit-account-A-2026-canary";
    private boolean authenticated;
    private boolean retained;
    private String account = "none";
    private TextView label;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        label = new TextView(this);
        label.setTextSize(22);
        label.setPadding(24, 96, 24, 24);
        setContentView(label);
        SharedPreferences preferences = getSharedPreferences("fixture", MODE_PRIVATE);
        authenticated = preferences.getBoolean("authenticated", false);
        retained = preferences.getBoolean("retained", false);
        account = preferences.getString("account", "none");
        route(getIntent());
    }

    @Override public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        route(intent);
    }

    private void write(String name, String value) {
        try { Files.write(new File(getFilesDir(), name).toPath(), value.getBytes(StandardCharsets.UTF_8)); }
        catch (Exception error) { throw new IllegalStateException("fixture write failed", error); }
    }

    private void route(Intent intent) {
        Uri uri = intent.getData();
        String path = uri == null ? "" : uri.getPath();
        if ("/prepare".equals(path)) {
            authenticated = true;
            retained = "retained".equals(uri.getQueryParameter("mode"));
            account = "A";
            write("account-cache.txt", ACCOUNT_A);
        } else if ("/logout".equals(path)) {
            authenticated = false;
            account = "none";
            if (!retained) new File(getFilesDir(), "account-cache.txt").delete();
        } else if ("/switch".equals(path)) {
            authenticated = true;
            account = "B";
            if (!retained) new File(getFilesDir(), "account-cache.txt").delete();
        }
        getSharedPreferences("fixture", MODE_PRIVATE).edit()
            .putBoolean("authenticated", authenticated).putBoolean("retained", retained)
            .putString("account", account).apply();
        String state = authenticated ? "Account " + account + " active" : "Signed out state";
        write("state.txt", state);
        if ("/protected".equals(path)) {
            label.setText((authenticated && "A".equals(account)) || (!authenticated && retained)
                ? "Protected screen: " + ACCOUNT_A : "Access denied");
        } else {
            label.setText(state + (authenticated && "A".equals(account) ? "\n" + ACCOUNT_A : ""));
        }
    }
}

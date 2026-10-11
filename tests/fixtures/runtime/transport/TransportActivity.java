package apsa.fixture.transport;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import org.json.JSONObject;
import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.concurrent.Executors;

/** NEW CI-only test fixture. No production accounts, UI capture or logging. */
public final class TransportActivity extends Activity {
    final java.util.concurrent.ExecutorService worker = Executors.newSingleThreadExecutor();
    String session = "", account = "", token = "", backend = "";
    boolean after = false, retain = false;
    String state = "";
    String hash(byte[] value) throws Exception {
        StringBuilder out = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(value)) out.append(String.format("%02x", b & 255));
        return out.toString();
    }
    String build() throws Exception { return hash(Files.readAllBytes(new File(getApplicationInfo().sourceDir).toPath())); }
    /** Finite diagnostic categories only; never expose exception messages or class names. */
    static String errorCategory(Exception error) {
        if (error instanceof java.net.SocketTimeoutException) return "socket-timeout";
        if (error instanceof java.net.ConnectException) return "connect";
        if (error instanceof java.net.UnknownHostException) return "host";
        if (error instanceof java.io.IOException) return "io";
        if (error instanceof org.json.JSONException) return "json";
        if (error instanceof SecurityException) return "security";
        if (error instanceof IllegalArgumentException) return "argument";
        if (error instanceof IllegalStateException) return "http-status";
        return "other";
    }
    JSONObject http(String route) throws Exception {
        HttpURLConnection conn = (HttpURLConnection)new URL(backend + route).openConnection();
        conn.setConnectTimeout(10000); conn.setReadTimeout(10000); conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        if (!token.isEmpty()) conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setDoOutput(true);
        JSONObject body = new JSONObject().put("session", session).put("package", getPackageName()).put("build", build());
        try (java.io.OutputStream out = conn.getOutputStream()) { out.write(body.toString().getBytes(StandardCharsets.UTF_8)); }
        if (conn.getResponseCode() != 200) throw new IllegalStateException("authority-status");
        byte[] bytes;
        try (java.io.InputStream input = conn.getInputStream()) { bytes = input.readAllBytes(); }
        conn.disconnect();
        return new JSONObject(new String(bytes, StandardCharsets.UTF_8));
    }
    void emit(JSONObject value) throws Exception {
        value.put("package", getPackageName()).put("apk_sha256", build()).put("session", session)
            .put("account", account).put("state", account.isEmpty() ? "logged_out" : "authenticated")
            .put("delivery", after ? "target-observed" : "baseline").put("delivery_transport", "android-os-intent");
        File temp = new File(getFilesDir(), "response.new");
        Files.write(temp.toPath(), value.toString().getBytes(StandardCharsets.UTF_8));
        Files.move(temp.toPath(), new File(getFilesDir(), "response.json").toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
    @Override public void onCreate(Bundle saved) { super.onCreate(saved); deliver(getIntent()); }
    @Override public void onNewIntent(Intent intent) { super.onNewIntent(intent); setIntent(intent); deliver(intent); }
    void deliver(Intent intent) {
        final Uri uri = intent.getData();
        worker.execute(() -> {
            String phase = "binding";
            try {
                if (!Intent.ACTION_VIEW.equals(intent.getAction()) || uri == null || !"apsatransport".equals(uri.getScheme()) || !"fixture".equals(uri.getHost())) throw new IllegalArgumentException();
                String challenge = uri.getQueryParameter("session"), action = uri.getQueryParameter("action");
                if (challenge == null || !challenge.matches("[a-f0-9]{64}")) throw new IllegalArgumentException();
                for (String key : uri.getQueryParameterNames()) if (uri.getQueryParameters(key).size() != 1) throw new IllegalArgumentException();
                if ("session".equals(action)) {
                    if (!session.isEmpty()) throw new IllegalArgumentException();
                    session = challenge; backend = uri.getQueryParameter("backend");
                    if (backend == null || !backend.matches("http://10\\.0\\.2\\.2:[0-9]+")) throw new IllegalArgumentException();
                    retain = "true".equals(uri.getQueryParameter("retain")); account = "a";
                    phase = "http-issue";
                    token = http("/issue").getString("credential");
                    state = "synthetic-unique-a synthetic-unique-login_a";
                    phase = "state-write";
                    Files.write(new File(getFilesDir(), "state.dat").toPath(), state.getBytes(StandardCharsets.UTF_8));
                    phase = "response-write";
                    emit(new JSONObject().put("action", action).put("fresh_store", true));
                } else {
                    if (!session.equals(challenge)) throw new IllegalArgumentException();
                    if ("transition".equals(action)) {
                        if (after || !"logout".equals(uri.getQueryParameter("kind"))) throw new IllegalArgumentException();
                        phase = "http-logout";
                        http("/logout"); account = ""; token = ""; after = true;
                        state = "synthetic-unique-state synthetic-unique-delivery" + (retain ? " synthetic-unique-a" : "");
                        phase = "state-write";
                        Files.write(new File(getFilesDir(), "state.dat").toPath(), state.getBytes(StandardCharsets.UTF_8));
                        phase = "response-write";
                        emit(new JSONObject().put("action", action).put("kind", "logout"));
                    } else if ("capture".equals(action)) {
                        String nonce = uri.getQueryParameter("nonce");
                        if (nonce == null || !nonce.matches("[a-f0-9]{64}") || !account.equals(uri.getQueryParameter("account")) || !(account.isEmpty() ? "logged_out" : "authenticated").equals(uri.getQueryParameter("state")) || !(after ? "logout" : "").equals(uri.getQueryParameter("transition"))) throw new IllegalArgumentException();
                        phase = "state-read";
                        String storage = new String(Files.readAllBytes(new File(getFilesDir(), "state.dat").toPath()), StandardCharsets.UTF_8);
                        phase = "response-write";
                        emit(new JSONObject().put("action", action).put("nonce", nonce).put("snapshot", uri.getQueryParameter("snapshot"))
                            .put("transition", after ? "logout" : "").put("completeness", "complete")
                            .put("storage", storage));
                    } else throw new IllegalArgumentException();
                }
            } catch (Exception error) {
                try {
                    JSONObject diagnostic = new JSONObject().put("schema_version", 1).put("phase", phase).put("category", errorCategory(error));
                    emit(new JSONObject().put("action", "fixture-error").put("code", "binding-or-transport").put("diagnostic", diagnostic));
                } catch (Exception suppressed) { }
            }
        });
    }
}

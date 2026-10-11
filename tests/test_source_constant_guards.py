"""Source regressions for typed constant fields and exact archive-entry identity."""

from mobile_audit.source_analysis import analyze_sources


def functions(text: str, path: str, rule: str) -> list[str]:
    return [
        item["evidence"][0]["function"]
        for item in analyze_sources([(path, text)])["findings"]
        if item["rule_id"] == rule
    ]


def test_typed_constant_fields_preserve_parameter_local_and_mutation_boundaries():
    text = """import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
class Fields {
    private static final String KEY = "new-synthetic-key";
    private static final byte[] IV = {1, 2, 3, 4};
    void fixed() {
        new SecretKeySpec(KEY.getBytes(), "AES");
        new IvParameterSpec(IV);
    }
    void parameter(String KEY, byte[] IV) {
        new SecretKeySpec(KEY.getBytes(), "AES");
        new IvParameterSpec(IV);
    }
    void local(String runtime, byte[] bytes) {
        String KEY = runtime;
        byte[] IV = bytes;
        new SecretKeySpec(KEY.getBytes(), "AES");
        new IvParameterSpec(IV);
    }
    void element(byte[] runtime) {
        IV[0] = runtime[0];
        new IvParameterSpec(IV);
    }
    void fill() {
        new SecureRandom().nextBytes(IV);
        new IvParameterSpec(IV);
    }
}"""
    assert functions(text, "Fields.java", "AST-CRYPTO-HARDCODED-KEY") == ["fixed"]
    assert functions(text, "Fields.java", "AST-CRYPTO-STATIC-IV") == ["fixed"]


def test_archive_name_guard_follows_only_the_same_entry_and_alias():
    text = """import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
class Archive {
    fun alias(zis: ZipInputStream, dest: File) {
        val entry = zis.nextEntry ?: return
        if (".." in entry.name) return
        val same = entry
        File(dest, same.name)
    }
    fun parameter(entry: ZipEntry, dest: File) {
        if (entry.name.contains("..")) return
        File(dest, entry.getName())
    }
    fun reassigned(zis: ZipInputStream, dest: File) {
        var entry = zis.nextEntry ?: return
        if (".." in entry.name) return
        entry = zis.nextEntry ?: return
        File(dest, entry.name)
    }
    fun different(zis: ZipInputStream, dest: File) {
        val first = zis.nextEntry ?: return
        if (".." in first.name) return
        val second = zis.nextEntry ?: return
        File(dest, second.name)
    }
    fun slash(entry: ZipEntry, dest: File) {
        if (entry.name.contains("../")) return
        File(dest, entry.name)
    }
    fun nested(entry: ZipEntry, dest: File, reject: Boolean) {
        if (".." in entry.name) { if (reject) return }
        File(dest, entry.name)
    }
}"""
    assert functions(text, "Archive.kt", "AST-PATH-TRAVERSAL") == [
        "reassigned",
        "different",
        "slash",
        "nested",
    ]

from __future__ import annotations

import textwrap

import pytest

from mobile_audit.source_analysis import analyze_sources

JAVA = """
import android.content.Intent;
import java.io.File;
import java.io.FileOutputStream;
class Saver {
    void save(Intent intent, File base, boolean trusted) throws Exception {
        String name = intent.getStringExtra("name");
        File target = new File(base, name);
        String canonical = target.getCanonicalPath();
        GUARD
        new FileOutputStream(canonical);
    }
}
"""
KOTLIN = """
import android.content.Intent
import java.io.File
import java.io.FileOutputStream
class Saver {
    fun save(intent: Intent, base: File, trusted: Boolean) {
        val name = intent.getStringExtra("name")!!
        val target = File(base, name)
        val canonical = target.canonicalPath
        GUARD
        FileOutputStream(canonical)
    }
}
"""
JAVA_CHECK = "canonical.startsWith(base.getCanonicalPath() + File.separator)"
KOTLIN_CHECK = "canonical.startsWith(base.canonicalPath + File.separator)"


def path_findings(language: str, guard: str) -> int:
    template, path = (JAVA, "app/Saver.java") if language == "java" else (KOTLIN, "app/Saver.kt")
    result = analyze_sources([(path, textwrap.dedent(template).replace("GUARD", guard).strip())])
    return sum(item["rule_id"] == "AST-PATH-TRAVERSAL" for item in result["findings"])


@pytest.mark.parametrize(
    ("language", "guard"),
    [
        ("java", f"if (trusted) {{ }} else if (!{JAVA_CHECK}) {{ return; }}"),
        ("java", f'if (trusted) {{ System.out.println("skip"); }} else if (!{JAVA_CHECK}) return;'),
        ("java", f"switch (name.length()) {{ case 1: if (!{JAVA_CHECK}) return; break; default: break; }}"),
        ("java", f"for (int i = 0; i < 1; i++) if (!{JAVA_CHECK}) return;"),
        ("kotlin", f'if (trusted) {{ println("skip") }} else if (!{KOTLIN_CHECK}) {{ return }}'),
        ("kotlin", f"when {{ trusted -> {{ }} else -> if (!{KOTLIN_CHECK}) return }}"),
    ],
)
def test_guard_inside_a_conditional_arm_does_not_protect_later_sinks(language, guard):
    assert path_findings(language, guard) == 1


@pytest.mark.parametrize(
    ("language", "guard"),
    [
        ("java", f"if (!{JAVA_CHECK}) {{ return; }}"),
        ("java", f"if (!{JAVA_CHECK}) return;"),
        ("java", f"if (!{JAVA_CHECK}) {{ throw new SecurityException(); }}"),
        ("kotlin", f"if (!{KOTLIN_CHECK}) return"),
        ("kotlin", f"if (!{KOTLIN_CHECK}) {{ throw SecurityException() }}"),
    ],
)
def test_statement_level_containment_guard_still_protects_later_sinks(language, guard):
    assert path_findings(language, guard) == 0

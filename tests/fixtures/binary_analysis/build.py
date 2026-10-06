"""Rebuild fixture APKs with javac and Android SDK d8; never install them."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--platform", default="android-36")
    parser.add_argument("--build-tools", default="36.0.0")
    args = parser.parse_args()
    javac = shutil.which("javac")
    if javac is None:
        raise SystemExit("javac is required to rebuild these fixtures")
    android_jar = args.sdk / "platforms" / args.platform / "android.jar"
    d8 = args.sdk / "build-tools" / args.build_tools / "d8"
    fixtures = Path(__file__).parent
    for variant in ("unsafe", "safe"):
        with tempfile.TemporaryDirectory(prefix="mobile-audit-bytecode-") as temporary:
            root = Path(temporary)
            classes, dex = root / "classes", root / "dex"
            classes.mkdir()
            dex.mkdir()
            subprocess.run(
                [
                    javac,
                    "--release",
                    "8",
                    "-classpath",
                    str(android_jar),
                    "-d",
                    str(classes),
                    str(fixtures / variant / "Calls.java"),
                ],
                check=True,
                timeout=60,
            )
            subprocess.run(
                [
                    str(d8),
                    "--lib",
                    str(android_jar),
                    "--min-api",
                    "23",
                    "--output",
                    str(dex),
                    str(classes / "audit/fixture/Calls.class"),
                ],
                check=True,
                timeout=60,
            )
            with zipfile.ZipFile(
                fixtures / f"{variant}.apk", "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                manifest = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="audit.fixture"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="36"/><application android:debuggable="false"/></manifest>'
                for name, raw in (
                    ("AndroidManifest.xml", manifest),
                    ("classes.dex", (dex / "classes.dex").read_bytes()),
                ):
                    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(entry, raw)


if __name__ == "__main__":
    main()

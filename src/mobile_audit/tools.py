from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def android_sdks() -> list[Path]:
    candidates = [
        Path(value).expanduser()
        for key in ("ANDROID_SDK_ROOT", "ANDROID_HOME")
        if (value := os.environ.get(key))
    ]
    candidates.extend([Path.home() / "Library/Android/sdk", Path.home() / "Android/Sdk"])
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        candidates.append(Path(os.environ["LOCALAPPDATA"]) / "Android/Sdk")
    return list(dict.fromkeys(path.resolve() for path in candidates if path.is_dir()))


def resolve_tool(name: str) -> str | None:
    if found := shutil.which(name):
        return found
    relative = {
        "adb": "platform-tools/adb",
        "emulator": "emulator/emulator",
        "sdkmanager": "cmdline-tools/latest/bin/sdkmanager",
        "avdmanager": "cmdline-tools/latest/bin/avdmanager",
        "apkanalyzer": "cmdline-tools/latest/bin/apkanalyzer",
    }.get(name)
    if relative:
        for sdk in android_sdks():
            candidate = sdk / relative
            if sys.platform == "win32":
                candidate = candidate.with_suffix(
                    ".bat" if name.endswith("manager") or name == "apkanalyzer" else ".exe"
                )
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None

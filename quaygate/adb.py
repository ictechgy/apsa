"""ADB 실행 래퍼. 테스트에서는 동일 인터페이스의 Fake 객체로 교체한다."""
from __future__ import annotations

import shutil
import subprocess


class AdbError(RuntimeError):
    """adb 실행 실패."""


class AdbUnavailable(AdbError):
    """adb 바이너리가 없거나 연결된 기기가 없다."""


class AdbRunner:
    """subprocess 기반 adb 래퍼. shell()/get_state()만 제공한다(읽기 전용 점검에 충분)."""

    def __init__(self, serial: str | None = None, adb_path: str | None = None) -> None:
        self.serial = serial
        self.adb_path = adb_path or shutil.which("adb") or "adb"

    def _base_cmd(self) -> list[str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def shell(self, *args: str, timeout: float = 20.0) -> str:
        cmd = self._base_cmd() + ["shell", *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout)
        except FileNotFoundError as exc:
            raise AdbUnavailable(
                "adb 바이너리를 찾을 수 없습니다 (macOS: brew install android-platform-tools)"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb shell {' '.join(args)} 시간 초과") from exc
        if proc.returncode != 0:
            raise AdbError(
                f"adb shell {' '.join(args)} 실패: {proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc.stdout

    def get_state(self) -> str:
        cmd = self._base_cmd() + ["get-state"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=10)
        except FileNotFoundError as exc:
            raise AdbUnavailable("adb 바이너리를 찾을 수 없습니다") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError("adb get-state 시간 초과") from exc
        return proc.stdout.strip()

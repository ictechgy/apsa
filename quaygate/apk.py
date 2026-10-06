"""APK 번들 접근 — ZIP 엔트리, 매니페스트, DEX 문자열, 서명 방식, 리소스 이름."""
from __future__ import annotations

import os
import re
import struct
import zipfile
import zlib

from . import arsc, dex

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


class ApkError(RuntimeError):
    """APK 열기/읽기 실패."""


class Apk:
    def __init__(self, path: str) -> None:
        self.path = path
        self._resource_names = None
        self._arsc_error = None
        self._dex_stats = None
        try:
            self.zipf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise ApkError(f"APK를 열 수 없습니다: {exc}") from exc

    def close(self) -> None:
        try:
            self.zipf.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.zipf.close()
        except Exception:
            pass

    def entry_names(self) -> list:
        return self.zipf.namelist()

    def read(self, name: str) -> bytes:
        try:
            return self.zipf.read(name)
        except KeyError as exc:
            raise ApkError(f"엔트리 없음: {name}") from exc
        except (RuntimeError, NotImplementedError, EOFError, OSError, zlib.error,
                zipfile.BadZipFile) as exc:
            # zipfile.BadZipFile은 Exception 직속이다 — 명시하지 않으면 CRC 불일치가
            # 여기 통과해 전체 감사를 죽인다. 미지원 압축/암호화/잘린 파일 포함.
            raise ApkError(f"엔트리 읽기 실패({name}): {type(exc).__name__}: {exc}") from exc

    def resource_names(self) -> dict:
        """리소스 ID(int) → (타입명, 엔트리명, 값). arsc가 없거나 파싱 실패 시 빈 dict."""
        if self._resource_names is None:
            names = {}
            if "resources.arsc" in self.entry_names():
                try:
                    names = arsc.parse_resource_names(self.read("resources.arsc"))
                except Exception as exc:  # 파싱 실패 사유 보존(해석 불가 표시용)
                    self._arsc_error = f"{type(exc).__name__}: {exc}"
                    names = {}
            self._resource_names = names
        return self._resource_names

    def dex_scan_stats(self) -> tuple:
        """(classes*.dex 개수, 읽기 실패 개수) — 지표 na/info 판정용."""
        if self._dex_stats is None:
            entries = [n for n in self.entry_names() if re.fullmatch(r"classes\d*\.dex", n)]
            errors = 0
            for name in entries:
                try:
                    dex.dex_strings(self.read(name))
                except (ValueError, ApkError):
                    errors += 1
            self._dex_stats = (len(entries), errors)
        return self._dex_stats

    def dex_strings(self) -> list:
        seen, out = set(), []
        for name in self.entry_names():
            if re.fullmatch(r"classes\d*\.dex", name):
                try:
                    for s in dex.dex_strings(self.read(name)):
                        if s not in seen:
                            seen.add(s)
                            out.append(s)
                except (ValueError, ApkError):
                    continue  # 손상 dex — 부분 결과라도 계속(실패 수는 dex_scan_stats)
        return out

    def v1_signature_files(self) -> list:
        return [n for n in self.entry_names()
                if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))]

    def has_v2_plus_signature(self) -> bool:
        """APK Signing Block(v2+) 여부 — 중앙 디렉터리 직전 16바이트 매직 확인."""
        try:
            size = os.path.getsize(self.path)
            with open(self.path, "rb") as f:
                f.seek(max(0, size - 65536))
                tail = f.read()
            eocd = tail.rfind(b"PK\x05\x06")
            if eocd < 0:
                return False
            (cd_size, cd_off) = struct.unpack_from("<II", tail, eocd + 12)
            eocd_abs = (size - len(tail)) + eocd
            # EOCD는 중앙 디렉터리 바로 뒤에 있어야 한다 — 어긋나면 위조/비정상
            if cd_off + cd_size > size + 22 or cd_off + cd_size != eocd_abs:
                return False
            if cd_off < 24:
                return False
            with open(self.path, "rb") as f:
                f.seek(cd_off - 24)
                footer = f.read(24)
                if footer[8:] != APK_SIG_BLOCK_MAGIC:
                    return False
                # 푸터 크기(매직 앞 u64)와 블록 첫 u64가 일치해야 정식 Signing Block
                (footer_size,) = struct.unpack("<Q", footer[:8])
                block_start = cd_off - 8 - footer_size
                if footer_size < 24 or block_start < 0:
                    return False
                f.seek(block_start)
                (head_size,) = struct.unpack("<Q", f.read(8))
            return head_size == footer_size
        except (OSError, struct.error):
            return False

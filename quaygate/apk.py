"""APK 번들 접근 — ZIP 엔트리, 매니페스트, DEX 문자열, 서명 방식, 리소스 이름."""

from __future__ import annotations

import os
import re
import stat
import struct
import tempfile
import zipfile
import zlib
from typing import Protocol, cast

from . import arsc, dex

MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ZIP_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_ZIP_ENTRIES = 20000


def _supported_zip_extra(handle, length, *, local_padding=False):
    """Walk bounded extra records without materializing their payloads."""
    end = handle.tell() + length
    while handle.tell() < end:
        remaining = end - handle.tell()
        header = handle.read(min(4, remaining))
        if len(header) != 4:
            if local_padding and len(header) == remaining and not any(header):
                return
            raise ValueError("Malformed ZIP directory extra field")
        kind, size = struct.unpack("<HH", header)
        if kind == 1 or size > end - handle.tell():
            raise ValueError("Unsupported ZIP64 or malformed ZIP directory extra field")
        handle.seek(size, 1)


def _preflight_zip_directory(handle, offset, size, entries):
    """Count physical CD records before ZipFile can allocate any ZipInfo."""
    end, cursor, count, first_local = offset + size, offset, 0, None
    local_headers, local_metadata = {}, 0
    while cursor < end:
        if end - cursor < 46:
            raise ValueError("Truncated ZIP directory header")
        handle.seek(cursor)
        header = handle.read(46)
        if len(header) != 46 or header[:4] != b"PK\x01\x02":
            raise ValueError("Malformed ZIP directory header")
        count += 1
        if count > MAX_ZIP_ENTRIES:
            raise ValueError("ZIP directory entry budget exceeded")
        compressed, uncompressed = struct.unpack_from("<II", header, 20)
        name_len, extra_len, comment_len, disk = struct.unpack_from("<4H", header, 28)
        (local_offset,) = struct.unpack_from("<I", header, 42)
        next_cursor = cursor + 46 + name_len + extra_len + comment_len
        if (
            not name_len
            or next_cursor > end
            or disk
            or 0xFFFFFFFF in (compressed, uncompressed, local_offset)
            or local_offset + 30 > offset
        ):
            raise ValueError("Unsupported ZIP directory entry layout")
        handle.seek(cursor + 46 + name_len)
        _supported_zip_extra(handle, extra_len)
        if local_offset not in local_headers:
            handle.seek(local_offset)
            local = handle.read(30)
            if len(local) != 30 or local[:4] != b"PK\x03\x04":
                raise ValueError("Malformed ZIP local header")
            local_compressed, local_uncompressed = struct.unpack_from("<II", local, 18)
            local_name, local_extra = struct.unpack_from("<HH", local, 26)
            local_end = local_offset + 30 + local_name + local_extra
            # Aliased local headers are inspected once. Distinct/overlapping
            # metadata cannot multiply work beyond the directory byte budget.
            local_metadata += 30 + local_name + local_extra
            if (
                0xFFFFFFFF in (local_compressed, local_uncompressed)
                or local_end > offset
                or local_metadata > MAX_ZIP_DIRECTORY_BYTES
            ):
                raise ValueError("Unsupported ZIP64 or ZIP local metadata budget/bounds")
            handle.seek(local_offset + 30 + local_name)
            _supported_zip_extra(handle, local_extra, local_padding=True)
            local_headers[local_offset] = local_end
        if local_headers[local_offset] + compressed > offset:
            raise ValueError("Unsupported ZIP local member bounds")
        first_local = local_offset if first_local is None else min(first_local, local_offset)
        cursor = next_cursor
    if count != entries or (count and first_local != 0) or (not count and offset != 0):
        raise ValueError("ZIP directory count or physical offset mismatch")


def _snapshot_zip_input(path):
    """Freeze finite input bytes before validating metadata or constructing ZipInfo."""
    snapshot = tempfile.TemporaryFile()
    try:
        with open(path, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARCHIVE_BYTES:
                raise ValueError("ZIP input exceeds supported snapshot byte limit")
            copied = 0
            while True:
                chunk = source.read(min(1024 * 1024, MAX_ARCHIVE_BYTES - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_ARCHIVE_BYTES:
                    raise ValueError("ZIP input exceeds supported snapshot byte limit")
                snapshot.write(chunk)
        snapshot.seek(0)
        return snapshot
    except BaseException:
        snapshot.close()
        raise


class _ZipStreamOwnership(Protocol):
    _filePassed: int


def bounded_zip(path):
    """Preflight frozen bytes before ZipInfo allocation; reject unsupported ZIP64."""
    handle = _snapshot_zip_input(path)
    try:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - 65557))
        tail = handle.read(65557)
        eocd = tail.rfind(b"PK\x05\x06")
        if eocd < 0 or eocd + 22 > len(tail):
            raise ValueError("Missing ZIP directory")
        disk, cd_disk, disk_entries, entries, cd_size, cd_off, comment = struct.unpack_from(
            "<HHHHIIH", tail, eocd + 4
        )
        eocd_offset = size - len(tail) + eocd
        # A maximum-length comment leaves the locator outside the retained tail.
        # ZipFile consults this locator even when all 32-bit EOCD values look safe.
        handle.seek(max(0, eocd_offset - 20))
        locator = handle.read(4) if eocd_offset >= 20 else b""
        if (
            disk
            or cd_disk
            or disk_entries != entries
            or entries == 0xFFFF
            or entries > MAX_ZIP_ENTRIES
            or cd_size == 0xFFFFFFFF
            or cd_size > MAX_ZIP_DIRECTORY_BYTES
            or cd_off == 0xFFFFFFFF
            or cd_off + cd_size != eocd_offset
            or locator == b"PK\x06\x07"
            or eocd + 22 + comment != len(tail)
        ):
            raise ValueError("ZIP directory exceeds supported limits")
        _preflight_zip_directory(handle, cd_off, cd_size, entries)
        archive = zipfile.ZipFile(handle)
        # Transfer the private snapshot to ZipFile's normal shared-stream
        # ownership: close it when the archive and its final member close.
        # This is the same stdlib flag used when ZipFile opens a filename.
        cast(_ZipStreamOwnership, archive)._filePassed = 0
        if len(archive.infolist()) > MAX_ZIP_ENTRIES:
            archive.close()
            raise ValueError("ZIP entry budget exceeded")
        return archive
    except BaseException:
        handle.close()
        raise


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


class ApkError(RuntimeError):
    """APK 열기/읽기 실패."""


class Apk:
    def __init__(self, path: str) -> None:
        self.path = path
        self._resource_names = None
        self._arsc_error = None
        self._dex_stats = None
        self._dex_strings = None
        self._read_bytes = 0
        try:
            self.zipf = bounded_zip(path)
        except (zipfile.BadZipFile, OSError, ValueError, struct.error) as exc:
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

    def read(self, name: str, limit: int = MAX_MEMBER_BYTES) -> bytes:
        """Read only supported members; never decompress then slice an oversized member."""
        try:
            info = self.zipf.getinfo(name)
            if limit < 0 or info.file_size > min(limit, MAX_MEMBER_BYTES):
                raise ApkError(f"엔트리 바이트 상한 초과: {name}")
            if self._read_bytes + info.file_size > MAX_TOTAL_BYTES:
                raise ApkError("APK 누적 읽기 바이트 상한 초과")
            with self.zipf.open(info) as handle:
                data = handle.read(min(limit, MAX_MEMBER_BYTES) + 1)
            self._read_bytes += len(data)
            if len(data) > limit or len(data) != info.file_size:
                raise ApkError(f"엔트리 크기 불일치/상한 초과: {name}")
            return data
        except KeyError as exc:
            raise ApkError(f"엔트리 없음: {name}") from exc
        except (RuntimeError, NotImplementedError, EOFError, OSError, zlib.error, zipfile.BadZipFile) as exc:
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

    def _scan_dex_strings(self):
        if self._dex_strings is not None:
            return
        entries = [n for n in self.entry_names() if re.fullmatch(r"classes\d*\.dex", n)]
        errors, total_bytes = 0, 0
        seen, out = set(), []
        for name in entries:
            try:
                values = dex.dex_strings(self.read(name))
                for value in values:
                    if value not in seen:
                        total_bytes += len(value.encode("utf-8"))
                        if total_bytes > dex.MAX_STRING_BYTES or len(out) >= dex.MAX_STRINGS:
                            raise ValueError("APK string output budget exceeded")
                        seen.add(value)
                        out.append(value)
            except (ValueError, ApkError):
                errors += 1
        self._dex_stats = (len(entries), errors)
        self._dex_strings = out

    def dex_scan_stats(self) -> tuple[int, int]:
        """(classes*.dex count, incomplete string-table count)."""
        self._scan_dex_strings()
        assert self._dex_stats is not None
        return self._dex_stats

    def dex_strings(self) -> list[str]:
        self._scan_dex_strings()
        assert self._dex_strings is not None
        return self._dex_strings

    def v1_signature_files(self) -> list:
        return [
            n for n in self.entry_names() if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))
        ]

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

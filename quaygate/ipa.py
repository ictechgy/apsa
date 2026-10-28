"""iOS IPA 번들 점검 — Info.plist 설정과 바이너리 문자열 지표(비탈옥·정적·읽기 전용)."""

from __future__ import annotations

import os
import plistlib
import re
import struct
import zipfile
import zlib

from . import indicators
from .apk import bounded_zip
from .checks import HIGH, INFO, LOW, MEDIUM, Finding

BINARY_SCAN_LIMIT = 32 * 1024 * 1024  # 대형 바이너리 대비 상한
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_TAIL_STRING_BYTES = 8 * 1024 * 1024
MAX_ASCII_CARRY = 64 * 1024
MAX_PLIST_BYTES = 8 * 1024 * 1024
ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")
MIN_SUPPORTED_MAJOR = 15  # 참고 기준(2026-10) — Apple은 버전별 지원을 공표하지 않아 보수 임계

FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF  # fat_arch_64(32바이트) 레코드
MH_PIE = 0x200000
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
_THIN_MAGICS = {
    0xFEEDFACE: ("<", False),
    0xFEEDFACF: ("<", True),
    0xCEFAEDFE: (">", False),
    0xCFFAEDFE: (">", True),
}


def _read_streaming(fh, limit):
    """Bound decompression, retained strings and incomplete runs independently."""
    head_parts, tail_strings, carry = [], [], b""
    head_size = total = retained = 0
    head_boundary_seeded = False
    tail_canary = truncated = partial = False
    while total < MAX_BINARY_BYTES:
        chunk = fh.read(min(4 * 1024 * 1024, MAX_BINARY_BYTES - total + 1))
        if not chunk:
            break
        if total + len(chunk) > MAX_BINARY_BYTES:
            chunk = chunk[: MAX_BINARY_BYTES - total]
            partial = True
        total += len(chunk)
        take = min(max(0, limit - head_size), len(chunk))
        if take:
            head_parts.append(chunk[:take])
            head_size += take
        tail = chunk[take:]
        if head_size == limit and not head_boundary_seeded:
            head_boundary_seeded = True
            suffix = re.search(rb"[\x20-\x7e]+$", head_parts[-1]) if head_parts else None
            if suffix:
                if len(suffix.group(0)) > MAX_ASCII_CARRY:
                    partial = True
                carry = suffix.group(0)[-MAX_ASCII_CARRY:]
        if tail:
            truncated = True
            buf = carry + tail
            if b"___stack_chk_fail" in buf:
                tail_canary = True
            carry = b""
            for match in ASCII_RUN_RE.finditer(buf):
                raw = match.group(0)
                if match.end() == len(buf):
                    if len(raw) > MAX_ASCII_CARRY:
                        partial = True
                    carry = raw[-MAX_ASCII_CARRY:]
                elif retained + len(raw) <= MAX_TAIL_STRING_BYTES and len(tail_strings) < 200000:
                    tail_strings.append(raw.decode("ascii"))
                    retained += len(raw)
                else:
                    partial = True
            if not carry:
                suffix = re.search(rb"[\x20-\x7e]{1,5}$", buf)
                carry = suffix.group(0) if suffix else b""
        if partial and total >= MAX_BINARY_BYTES:
            break
    if total == MAX_BINARY_BYTES and not partial:
        partial = bool(fh.read(1))
    if len(carry) >= 6:
        if retained + len(carry) <= MAX_TAIL_STRING_BYTES and len(tail_strings) < 200000:
            tail_strings.append(carry.decode("ascii"))
        else:
            partial = True
    return b"".join(head_parts), tail_strings, tail_canary, truncated, partial


class IpaError(RuntimeError):
    """IPA 열기/읽기 실패."""


def _slice_cryptid(data: bytes, offset: int):
    if offset + 32 > len(data):
        return None
    (magic,) = struct.unpack_from("<I", data, offset)
    spec = _THIN_MAGICS.get(magic)
    if spec is None:
        return None
    endian, is64 = spec
    (ncmds,) = struct.unpack_from(endian + "I", data, offset + 16)
    pos = offset + (32 if is64 else 28)
    for _ in range(min(ncmds, 65536)):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, pos)
        if cmdsize < 8:
            break
        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and pos + 20 <= len(data):
            (cryptid,) = struct.unpack_from(endian + "I", data, pos + 16)
            return cryptid
        pos += cmdsize
    return None


def _iter_fat_slices(data: bytes):
    """FAT/FAT64 헤더에서 (슬라이스 오프셋, 크기) 목록 — 공통 파서."""
    if len(data) < 8:
        return []
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return []
    is64 = magic == FAT_MAGIC_64
    arch_size = 32 if is64 else 20
    fmt = ">IIQQQ" if is64 else ">IIIII"  # fat_arch_64은 offset/size/align이 u64
    (nfat,) = struct.unpack_from(">I", data, 4)
    slices = []
    for i in range(min(nfat, 16)):
        base = 8 + arch_size * i
        if base + arch_size > len(data):
            break
        fields = struct.unpack_from(fmt, data, base)
        slices.append((fields[2], fields[3]))
    return slices


def macho_cryptid(data: bytes):
    """FairPlay 암호화(cryptid) 감지 — 0 평문, 1 이상 암호화, None 판단 불가.

    App Store 배포 바이너리는 슬라이스가 암호화되어 문자열 지표 스캔이 무의미하다.
    이를 감지해 '확인불가'로 처리하기 위한 최소 Mach-O 로드 커맨드 파서다.
    """
    if len(data) < 8:
        return None
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        values = [_slice_cryptid(data, off) for off, _size in _iter_fat_slices(data)]
        encrypted = [v for v in values if v]
        if encrypted:
            return encrypted[0]
        plain = [v for v in values if v is not None]
        return plain[0] if plain else None
    return _slice_cryptid(data, 0)


def _slice_has_pie(data: bytes, offset: int) -> bool | None:
    if offset + 28 > len(data):
        return None
    (magic,) = struct.unpack_from("<I", data, offset)
    spec = _THIN_MAGICS.get(magic)
    if spec is None:
        return None
    endian, _is64 = spec
    (flags,) = struct.unpack_from(endian + "I", data, offset + 24)
    return bool(flags & MH_PIE)


def macho_hardening(data: bytes, *, truncated: bool = False) -> dict:
    """{pie, canary, macho} — 카나리는 심볼 문자열(___stack_chk_fail) 탐지 휴리스틱."""
    result: dict[str, bool | None] = {"pie": False, "canary": False, "macho": False}
    if len(data) < 8:
        return result
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        result["macho"] = True
        slices = _iter_fat_slices(data)
        values = [
            _slice_has_pie(data, off) if size >= 28 and (truncated or off + size <= len(data)) else None
            for off, size in slices
        ]
        result["pie"] = (
            False if False in values else (True if values and all(v is True for v in values) else None)
        )
    else:
        (le_magic,) = struct.unpack_from("<I", data, 0)
        if le_magic in _THIN_MAGICS:
            result["macho"] = True
            result["pie"] = _slice_has_pie(data, 0)
    result["canary"] = b"___stack_chk_fail" in data
    return result


class Ipa:
    def __init__(self, path: str) -> None:
        self.path = path
        try:
            self.zipf = bounded_zip(path)
        except (zipfile.BadZipFile, OSError, ValueError, struct.error) as exc:
            raise IpaError(f"IPA를 열 수 없습니다: {exc}") from exc

    def close(self) -> None:
        try:
            self.zipf.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_metadata(self, name):
        info = self.zipf.getinfo(name)
        if info.file_size > MAX_PLIST_BYTES:
            raise IpaError("IPA metadata byte budget exceeded")
        with self.zipf.open(info) as handle:
            value = handle.read(MAX_PLIST_BYTES + 1)
        if len(value) > MAX_PLIST_BYTES or len(value) != info.file_size:
            raise IpaError("IPA metadata truncated/budget exceeded")
        return value

    def info_plist(self) -> dict:
        names = [n for n in self.zipf.namelist() if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
        if not names:
            raise IpaError("Payload/*.app/Info.plist 없음 — IPA가 아니거나 손상되었습니다")
        try:
            raw = self._read_metadata(names[0])
        except (RuntimeError, NotImplementedError, EOFError, OSError, zipfile.BadZipFile, zlib.error) as exc:
            raise IpaError(f"Info.plist 읽기 실패: {type(exc).__name__}: {exc}") from exc
        try:
            value = plistlib.loads(raw)
            if not isinstance(value, dict):
                raise IpaError("Info.plist root must be a dictionary")
            return value
        except Exception as exc:  # 손상된 plist는 여러 예외 타입을 던진다(AttributeError, LookupError 등)
            raise IpaError(f"Info.plist 파싱 실패: {type(exc).__name__}: {exc}") from exc

    def app_binary(self) -> bytes:
        """실행 파일 앞부분(BINARY_SCAN_LIMIT). 초과분은 스트리밍으로 문자열/카나리만 수집."""
        if hasattr(self, "_binary"):
            return self._binary
        info = self.info_plist()
        executable = info.get("CFBundleExecutable")
        best_name, best_size = None, -1
        for n in self.zipf.namelist():
            if not re.fullmatch(r"Payload/[^/]+\.app/[^/]+", n) or n.endswith(".plist"):
                continue
            if executable and os.path.basename(n) == executable:
                best_name = n
                break
            size = self.zipf.getinfo(n).file_size
            if size > best_size:
                best_name, best_size = n, size
        if best_name is None:
            self._tail_strings, self._tail_canary, self._truncated = [], False, False
            self._binary, self._stream_partial = b"", False
            return self._binary
        try:
            with self.zipf.open(best_name) as fh:
                head, tail_strings, tail_canary, truncated, partial = _read_streaming(fh, BINARY_SCAN_LIMIT)
        except (RuntimeError, NotImplementedError, EOFError, OSError, zipfile.BadZipFile, zlib.error) as exc:
            raise IpaError(f"실행 파일 읽기 실패: {type(exc).__name__}: {exc}") from exc
        self._tail_strings, self._tail_canary, self._truncated = tail_strings, tail_canary, truncated
        self._binary, self._stream_partial = head, partial
        return head

    def embedded_provisioning(self) -> dict:
        """embedded.mobileprovision의 plist 부분 — 개발/엔터프라이즈 서명 메타."""
        names = [
            n
            for n in self.zipf.namelist()
            if re.fullmatch(r"Payload/[^/]+\.app/embedded\.mobileprovision", n)
        ]
        self._provisioning_state = "not-present" if not names else "unreadable"
        if not names:
            return {}
        try:
            raw = self._read_metadata(names[0])
        except (
            IpaError,
            RuntimeError,
            NotImplementedError,
            EOFError,
            OSError,
            zipfile.BadZipFile,
            zlib.error,
        ):
            return {}
        start = raw.find(b"<?xml")
        end = raw.rfind(b"</plist>")
        if start < 0 or end < 0 or end <= start:
            return {}
        try:
            value = plistlib.loads(raw[start : end + len(b"</plist>")])
            if not isinstance(value, dict):
                return {}
            self._provisioning_state = "parsed-unverified"
            return value
        except Exception:  # 손상된 프로비저닝 plist는 미확인으로 둔다
            return {}

    def binary_strings(self) -> list:
        head_strings = [
            m.group(0).decode("ascii", "replace") for m in ASCII_RUN_RE.finditer(self.app_binary())
        ]
        return head_strings + getattr(self, "_tail_strings", [])


def audit_ipa(ipa: Ipa) -> tuple:
    info = ipa.info_plist()
    findings: list = []

    ats = info.get("NSAppTransportSecurity") or {}
    ats_invalid = not isinstance(ats, dict)
    if ats_invalid:
        ats = {}
    exceptions = ats.get("NSExceptionDomains") or {}
    if not isinstance(exceptions, dict):
        ats_invalid, exceptions = True, {}
    min_os_major = None
    raw_min = str(info.get("MinimumOSVersion") or "")
    if raw_min.split(".")[0].isdigit():
        min_os_major = int(raw_min.split(".")[0])
    override_keys = [
        k
        for k in (
            "NSAllowsArbitraryLoadsInWebContent",
            "NSAllowsArbitraryLoadsForMedia",
            "NSAllowsLocalNetworking",
        )
        if ats.get(k)
    ]
    if ats.get("NSAllowsArbitraryLoads"):
        if min_os_major is not None and min_os_major >= 10 and override_keys:
            findings.append(
                Finding(
                    "ipa-ats",
                    "ATS 전역 해제(범위 한정)",
                    "warn",
                    LOW,
                    f"NSAllowsArbitraryLoads=true이나 iOS 10+에서 {', '.join(override_keys)}가 함께 "
                    "선언되어 일반 네트워크 호출에는 무시되고 해당 범위에만 적용됩니다.",
                    "웹 콘텐츠/미디어 평문 허용이 의도인지 확인하세요.",
                )
            )
        else:
            findings.append(
                Finding(
                    "ipa-ats",
                    "ATS 전역 해제",
                    "warn",
                    MEDIUM,
                    "NSAllowsArbitraryLoads=true — 평문 http 포함 전 도메인 허용.",
                    "필요 도메인만 NSExceptionDomains로 예외화하고 기본 ATS를 유지하세요.",
                )
            )
    else:
        findings.append(
            Finding(
                "ipa-ats",
                "ATS 전역 해제",
                "pass",
                None,
                "전역 해제 없음" + ("(예외 도메인 있음)" if ats.get("NSExceptionDomains") else "."),
            )
        )
    insecure_domains = []
    for domain, domain_cfg in exceptions.items():
        if not isinstance(domain_cfg, dict):
            ats_invalid = True
            continue
        insecure = domain_cfg.get(
            "NSExceptionAllowsInsecureHTTPLoads",
            domain_cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads"),
        )
        if insecure:
            insecure_domains.append(str(domain))
    if insecure_domains:
        findings.append(
            Finding(
                "ipa-ats-domains",
                "ATS 도메인 평문 예외",
                "warn",
                LOW,
                f"평문 허용 예외 도메인 {len(insecure_domains)}개: {', '.join(insecure_domains[:8])}",
                "해당 도메인의 TLS 예외가 여전히 필요한지 검토하세요.",
            )
        )
    else:
        findings.append(
            Finding("ipa-ats-domains", "ATS 도메인 평문 예외", "pass", None, "평문 예외 도메인 없음.")
        )

    if info.get("UIFileSharingEnabled"):
        findings.append(
            Finding(
                "ipa-file-sharing",
                "iTunes 파일 공유",
                "info",
                INFO,
                "UIFileSharingEnabled=true — Documents가 Finder/iTunes에 노출됩니다.",
                "공유가 필요한 파일만 Documents에 두고 민감 데이터는 Application Support 등으로 옮기세요.",
            )
        )
    else:
        findings.append(
            Finding("ipa-file-sharing", "iTunes 파일 공유", "pass", None, "꺼짐(또는 선언 없음).")
        )

    url_types = info.get("CFBundleURLTypes", [])
    schemes, schemes_invalid = set(), not isinstance(url_types, list)
    for url_type in url_types if isinstance(url_types, list) else []:
        if not isinstance(url_type, dict):
            schemes_invalid = True
            continue
        values = url_type.get("CFBundleURLSchemes", [])
        if not isinstance(values, list):
            schemes_invalid = True
            continue
        for value in values:
            if isinstance(value, str):
                schemes.add(value)
            else:
                schemes_invalid = True
    schemes = sorted(schemes)
    if schemes:
        findings.append(
            Finding(
                "ipa-url-schemes",
                "커스텀 URL 스킴",
                "info",
                INFO,
                f"{len(schemes)}개: {', '.join(schemes[:10])}",
                "스킴 가로채기(hijack)에 노출됩니다. 범용 링크(universal links)와 입력 검증을 검토하세요.",
            )
        )
    if schemes_invalid:
        findings.append(
            Finding(
                "ipa-url-schemes",
                "커스텀 URL 스킴",
                "na",
                None,
                "URL 스킴 설정 구조가 잘못되어 전체를 해석할 수 없습니다.",
            )
        )
    elif not schemes:
        findings.append(Finding("ipa-url-schemes", "커스텀 URL 스킴", "pass", None, "선언 없음."))

    entitlements = ipa.embedded_provisioning().get("Entitlements") or {}
    if not isinstance(entitlements, dict):
        entitlements = {}
    if entitlements.get("get-task-allow"):
        findings.append(
            Finding(
                "ipa-get-task-allow",
                "개발 서명(get-task-allow)",
                "fail",
                HIGH,
                "provisioning entitlements에 get-task-allow=true — 디버거/디버깅 허용 상태로 서명되었습니다.",
                "배포용(App Store/Ad-hoc) 프로비저닝 프로파일로 재서명하세요.",
            )
        )
    else:
        findings.append(
            Finding(
                "ipa-get-task-allow",
                "개발 서명(get-task-allow)",
                "na",
                None,
                f"실제 서명 entitlement 판단 불가 — profile: {getattr(ipa, '_provisioning_state', 'unknown')}.",
            )
        )

    min_os = str(info.get("MinimumOSVersion") or "")
    major = int(min_os.split(".")[0]) if min_os.split(".")[0].isdigit() else None
    if major is None:
        findings.append(Finding("ipa-min-os", "최소 지원 OS", "na", None, "MinimumOSVersion 확인 불가."))
    elif major < MIN_SUPPORTED_MAJOR:
        findings.append(
            Finding(
                "ipa-min-os",
                "최소 지원 OS",
                "warn",
                MEDIUM,
                f"MinimumOSVersion={min_os}(<{MIN_SUPPORTED_MAJOR}) — 오래된 iOS 보안 업데이트 미적용 사용자 포함.",
                "최소 버전을 올려 구형 OS 잔존을 줄이세요.",
            )
        )
    else:
        findings.append(Finding("ipa-min-os", "최소 지원 OS", "pass", None, f"MinimumOSVersion={min_os}."))

    binary = ipa.app_binary()
    truncated = getattr(ipa, "_truncated", False)
    tail_canary = getattr(ipa, "_tail_canary", False)
    hard = macho_hardening(binary, truncated=truncated)
    scan_partial = getattr(ipa, "_stream_partial", False)
    scan_note = " — 상한 초과분 스트리밍(바이트·문자열 예산 적용)" if truncated else ""
    if hard["macho"]:
        if hard["pie"] is None:
            findings.append(
                Finding(
                    "ipa-binary-hardening",
                    "바이너리 하드닝",
                    "na",
                    None,
                    "일부 Mach-O 헤더를 확인할 수 없어 전체 아키텍처의 PIE 적용 여부를 판단할 수 없습니다.",
                )
            )
        elif not hard["pie"]:
            findings.append(
                Finding(
                    "ipa-binary-hardening",
                    "바이너리 하드닝",
                    "warn",
                    MEDIUM,
                    "PIE 플래그 없음 — ASLR 미적용으로 메모리 익스플로잇 완화가 약합니다.",
                    "빌드 설정에서 PIE를 활성화하세요(기본값).",
                )
            )
        elif scan_partial and not (hard["canary"] or tail_canary):
            findings.append(
                Finding(
                    "ipa-binary-hardening",
                    "바이너리 하드닝",
                    "na",
                    None,
                    "스트리밍 예산 초과로 카나리 부재를 판단할 수 없습니다.",
                )
            )
        elif not (hard["canary"] or tail_canary):
            findings.append(
                Finding(
                    "ipa-binary-hardening",
                    "바이너리 하드닝",
                    "warn",
                    LOW,
                    "스택 카나리 심볼(___stack_chk_fail) 미탐지 — 스택 오버플로 완화 부재 가능.",
                    "-fstack-protector-strong 활성화를 확인하세요(심볼 문자열 탐지 휴리스틱).",
                )
            )
        else:
            findings.append(
                Finding(
                    "ipa-binary-hardening",
                    "바이너리 하드닝",
                    "pass",
                    None,
                    "PIE·스택 카나리 적용(심볼 문자열 탐지)." + scan_note,
                )
            )
    else:
        findings.append(
            Finding("ipa-binary-hardening", "바이너리 하드닝", "na", None, "Mach-O 바이너리 판단 불가.")
        )

    cryptid = macho_cryptid(binary)
    if cryptid:
        findings.append(
            Finding(
                "bin-scan",
                "바이너리 문자열 지표",
                "na",
                None,
                f"FairPlay 암호화 바이너리(cryptid={cryptid}) — 문자열 지표 스캔 불가. Info.plist 점검만 유효합니다.",
                "재서명(탈 FairPlay) 사본이나 개발 빌드로 다시 점검하세요.",
            )
        )
    elif not binary:
        findings.append(
            Finding(
                "bin-scan",
                "바이너리 문자열 지표",
                "na",
                None,
                "실행 파일을 찾지 못했거나 비어 있습니다 — 지표 스캔 불가.",
                "IPA 구조를 확인하세요.",
            )
        )
    else:
        findings += indicators.audit_strings(
            ipa.binary_strings(), "bin", "바이너리 문자열 스캔 휴리스틱" + ("·스트리밍" if truncated else "")
        )

    if scan_partial:
        for item in findings:
            if item.check_id.startswith("bin-") and item.status == "pass":
                item.status, item.severity = "na", None
                item.detail += " — 바이트/문자열 예산 초과로 부분 스캔."
        findings.append(
            Finding(
                "bin-scan-scope",
                "바이너리 스캔 범위",
                "na",
                None,
                "바이트/문자열/연속 ASCII 예산 초과 — 전체 스캔을 완료하지 못했습니다.",
            )
        )
    for item in findings:
        if item.check_id in {"ipa-ats", "ipa-ats-domains"} and ats_invalid and item.status == "pass":
            item.status, item.severity, item.detail = (
                "na",
                None,
                "ATS 설정 구조가 잘못되어 해석할 수 없습니다.",
            )

    meta = {
        "type": "ipa",
        "file": os.path.basename(ipa.path),
        "bundle_id": info.get("CFBundleIdentifier"),
        "version": info.get("CFBundleShortVersionString"),
        "min_os": min_os or None,
    }
    return meta, findings

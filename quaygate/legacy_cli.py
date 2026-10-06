"""명령줄 진입점 — apk / ipa / device 하위 명령."""
from __future__ import annotations

import argparse
import os
import struct
import sys

from . import __version__
from .adb import AdbError, AdbRunner
from .apk import Apk, ApkError
from .appchecks import audit_apk
from .apps import audit_apps, collect_apps, list_third_party
from .checks import INFO, Finding, parse_getprop, run_device_checks
from .ipa import Ipa, IpaError, audit_ipa
from .report import exit_code, render_json, render_sarif, render_text


def _positive_int(value):
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError("1 이상의 정수여야 합니다")
    return ivalue


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apsa",
        description="모바일 앱 정적 점검(apk/ipa — 대상 파일은 수정하지 않음) + Android 기기 자가 점검(device — adb 읽기 전용). 본인·승인 대상만.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_apk = sub.add_parser("apk", help="APK 정적 점검(매니페스트·서명·DEX 문자열 지표)")
    p_apk.add_argument("path", help="APK 파일 경로")
    p_apk.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    p_apk.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 출력(code scanning 업로드용)")

    p_ipa = sub.add_parser("ipa", help="IPA 정적 점검(Info.plist·바이너리 문자열 지표)")
    p_ipa.add_argument("path", help="IPA 파일 경로")
    p_ipa.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    p_ipa.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 출력(code scanning 업로드용)")

    p_dev = sub.add_parser("device", help="연결된 Android 기기 자가 점검(adb 읽기 전용)")
    p_dev.add_argument("--serial", help="adb 직렬 번호(기기 여러 대일 때)")
    p_dev.add_argument("--skip-apps", action="store_true", help="앱 점검 생략(기기 설정만)")
    p_dev.add_argument("--max-apps", type=_positive_int, default=200, help="덤프할 서드파티 앱 상한(기본 200)")
    p_dev.add_argument("--json", action="store_true", help="JSON 리포트 출력")
    p_dev.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 출력(code scanning 업로드용)")
    return parser


def _emit(meta: dict, desc: str, findings: list, as_json: bool, sarif_uri: str = None) -> int:
    if sarif_uri is not None:
        print(render_sarif(sarif_uri, findings))
    elif as_json:
        print(render_json(meta, findings))
    else:
        print(render_text(desc, findings))
    return exit_code(findings)


def run_apk(args) -> int:
    try:
        apk = Apk(args.path)
        meta, findings = audit_apk(apk)
    except (ApkError, ValueError, struct.error) as exc:
        print(f"APK 점검 실패: {exc}", file=sys.stderr)
        return 2
    desc = f"{meta.get('file', '?')} — {meta.get('package') or '?'} v{meta.get('versionName') or '?'} (targetSdk {meta.get('targetSdk') or '?'})"
    return _emit(meta, desc, findings, args.json,
                 sarif_uri=os.path.basename(args.path) if args.sarif else None)


def run_ipa(args) -> int:
    try:
        ipa = Ipa(args.path)
        meta, findings = audit_ipa(ipa)
    except (IpaError, ValueError, struct.error) as exc:
        print(f"IPA 점검 실패: {exc}", file=sys.stderr)
        return 2
    desc = f"{meta.get('file', '?')} — {meta.get('bundle_id') or '?'} v{meta.get('version') or '?'} (minOS {meta.get('min_os') or '?'})"
    return _emit(meta, desc, findings, args.json,
                 sarif_uri=os.path.basename(args.path) if args.sarif else None)


def run_device(args, runner) -> int:
    try:
        state = runner.get_state()
        if state != "device":
            print(
                f"기기가 준비되지 않았습니다(state={state or '없음'}). USB 연결, USB 디버깅, 화면의 PC 승인을 확인하세요.",
                file=sys.stderr,
            )
            return 2
        props = parse_getprop(runner.shell("getprop"))
        findings = run_device_checks(runner, props)
        if not args.skip_apps:
            all_names = list_third_party(runner)
            names = all_names[: args.max_apps]
            infos, errors = collect_apps(runner, names)
            findings += audit_apps(infos, errors)
            if len(all_names) > len(names):
                findings.append(Finding(
                    "apps-truncated", "앱 점검 범위", "info", INFO,
                    f"{len(all_names) - len(names)}개 앱은 --max-apps 상한({args.max_apps}) 초과으로 생략.",
                    "--max-apps를 올려 재실행하세요.",
                ))
    except AdbError as exc:
        print(f"adb 오류: {exc}", file=sys.stderr)
        return 2
    meta = {
        "type": "device",
        "model": props.get("ro.product.model"),
        "manufacturer": props.get("ro.product.manufacturer"),
        "release": props.get("ro.build.version.release"),
        "sdk": props.get("ro.build.version.sdk"),
        "security_patch": props.get("ro.build.version.security_patch"),
    }
    desc = f"{meta['model'] or '?'}, Android {meta['release'] or '?'} (보안 패치 {meta['security_patch'] or '?'})"
    return _emit(meta, desc, findings, args.json,
                 sarif_uri=(args.serial or "device") if args.sarif else None)


def main(argv=None, runner=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # Windows 코드페이지 리디렉션 대비
    except (AttributeError, ValueError, OSError):
        pass
    args = build_parser().parse_args(argv)
    try:
        if args.command == "apk":
            return run_apk(args)
        if args.command == "ipa":
            return run_ipa(args)
        return run_device(args, runner or AdbRunner(args.serial))
    except SystemExit:
        raise
    except Exception as exc:  # 최종 안전망 — 종료 코드 계약(2=도구 오류) 유지
        print(f"apsa 내부 오류: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

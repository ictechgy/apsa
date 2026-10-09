# 지원 범위와 검증 상태

아래 호스트·CI 행은 배포된 1.1.0의 검증 기록이며, 대상 표에는 1.2의 범위를 함께 표시합니다. 1.2.0의 AAB·IPA 내장 바이너리,
Objective-C `.m`·OS 격리 범위는 [분석 확장](NEXT_ANALYSIS.md)과
[별도 검증 결과](../benchmarks/NEXT_RESULTS.ko.md)에 기록하며, 1.2.0 배포 확인은
`RELEASE_READINESS.md`의 태그 워크플로 기록을 따릅니다.

2026-10-08 기준입니다. 현재 GitHub CI 실행 근거는 [1.1.0 릴리스 워크플로](https://github.com/ictechgy/apsa/actions/runs/37796258526)이며, 아래 CI 통과는 태그 `v1.1.0`의 소스 스냅샷에 한정됩니다. 최종 버전·소스 스냅샷의 통과 여부는 릴리스 manifest와 `RELEASE_READINESS.md`를 확인하십시오. 아래에서 실행한 환경과 구성만 한 환경을 구분합니다. 새 실기기 검증을 수행했다는 뜻은 아닙니다.

| 호스트 / Python | 상태 | 검증 범위 |
| --- | --- | --- |
| macOS 27.0.1 / Apple Silicon / CPython 3.12.13 | 로컬 실행 | 단위·통합 검사, Java/Kotlin/Swift AST와 APK/IPA fixture, 독립 corpus, CLI/TUI/MCP 검사, 깨끗한 wheel 설치·오프라인 소스 smoke |
| Debian 12 Docker / ARM64 / CPython 3.12.13 | 컨테이너 실행 | 245개 pytest, Ruff check/format, Pyright, 31개 corpus, 1.0.0 online 준비·offline 캐시 릴리스 반복 빌드와 깨끗한 설치 smoke 모두 통과. SDK·기기 검사 없음 |
| GitHub `macos-15` / CPython 3.11.15 및 3.12.13 | 1.1.0 GitHub CI 통과 | 잠긴 테스트·corpus·wheel/sdist 반복 빌드·깨끗한 설치 smoke; 기기 검사 없음 |
| GitHub `ubuntu-24.04` / CPython 3.11.15 및 3.12.13 | 1.1.0 GitHub CI 통과 | 동일한 정적·배포 검사; iOS 런타임 없음 |
| Windows / Python 3.13 이상 / PyPy | 검증·지원 선언 없음 | 유한 파서와 런타임 잠금은 POSIX 전용 |

macOS 로컬 릴리스 smoke는 현재 버전으로 실제 실행했습니다. 다른 OS의 설치 성공이나 호환성을 추정해서 통과로 표시하지 않습니다. CI는 전체 commit SHA로 `actions/checkout` v7.0.0과 `astral-sh/setup-uv` v10.2.0을 고정하고 uv 0.12.1, Python patch 버전, `uv.lock`을 사용합니다. 호스팅 runner 이미지·SDK는 이 잠금에 포함되지 않습니다. Python 핀은 검증 재현용이며 최신 보안 패치라는 선언이 아닙니다. 갱신은 재검증과 함께 수행합니다.

Linux 실행은 `python@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2` 이미지, Linux 6.12.76-linuxkit/glibc 2.36, uv 0.12.1과 해시를 고정한 Node 24.12.0에서 수행했습니다. 허용한 소스 스냅샷을 컨테이너로 스트리밍하고 결과를 회수한 뒤 해당 컨테이너를 삭제했습니다. Docker Desktop 파일 공유 설정은 바꾸지 않았습니다. 설치 준비는 네트워크를 사용했고 두 번째 릴리스는 uv `--offline` 캐시 설치를 사용했습니다. 네트워크 namespace 자체를 차단한 검증이라는 주장은 하지 않습니다. 내부 증거에는 이미지·소스 해시, 실제 명령·종료 코드·로그·SBOM·릴리스 manifest가 있습니다. Debian ARM64의 결과를 Ubuntu x64 또는 Python 3.11의 실행 결과로 확대하지 않습니다.

| 대상 | 실제 검사 / 증거 | 범위와 제한 |
| --- | --- | --- |
| Android 소스 | Java/Kotlin 구조 분석과 소스 설정 fixture | WebView·딥링크 관련 함수 내 흐름 후보, Manifest/네트워크 설정·의존성. 클래스 간 완전한 taint·반사·redirect·전체 앱 실행 증명 없음 |
| iOS 소스 | Swift 구조 분석, 1.2의 제한된 Objective-C `.m` CST 후보와 설정 fixture | WKWebView/URL·호스트 검사 후보와 ATS·의존성. Objective-C `.m`은 항상 부분 분석이며 `.mm`·매크로·동적 dispatch·C/C++·Dart·JavaScript·프로젝트 전체 의미 분석은 미지원 범위를 표시 |
| APK | 직접 생성한 안전/위험 DEX fixture와 실제 APK | Android 설정, DEX 구조·호출·제어 흐름 후보, 인증서·빌드 의존성. 난독화·동적 로드·native 동작은 제한 |
| AAB (1.2) | 새로 생성한 합성 base-only AAB와 AAPT2 `dump xmltree` 교차검증 | AAPT2 protobuf base 매니페스트·모듈 DEX. 항상 부분 감사이며 리소스·feature 병합, 기기 targeting, 설치 split, APK 서명·ELF lint는 미지원 |
| IPA | Mach-O fixture와 직접 빌드한 iOS 시뮬레이터 앱, 1.2의 내장 framework·확장 메타데이터 | Mach-O·서명/entitlement·ATS 및 일부 바이너리 증거. 암호화된 실행 파일, 모든 native 함수의 의미와 실제 iOS 기기 실행은 보장하지 않음 |
| Android 런타임 | ARM64 `google_apis` API 37 에뮬레이터, 관찰 OS Android 17·보안 패치 2026-05-05; fixture는 SDK platform 36으로 컴파일 | 승인된 테스트 앱의 설치·package/hash 연결, 보관·로그인 상태 fixture, 증거 캡처. 앱 fixture 범위의 로컬 상태 검사이며 서버 세션 폐기 증명 아님 |
| iOS 런타임 | iPhone 18 Pro / iOS 27.0 시뮬레이터, 직접 빌드한 fixture | app container·현재 상태·바이너리 해시 연결. UI 구동·시스템 로그 캡처는 `not-run`, 실제 iOS 기기는 미지원 |
| 모델 연결 | 실제 Codex CLI MCP stdio에서 capabilities·reports_list·reports_get 실행 | 표준 MCP 연결 통로. Claude/Gemini 등 다른 모델 클라이언트는 실제 연결 검증 전 |
| 독립 정확도 corpus | 31개의 수작업 사례, rule/status별 ground truth | 10개 AST/DEX 규칙의 유한 회귀 사례. 모집단 정확도·운영 앱 탐지율·MASVS 인증으로 일반화 불가 |

런타임 증거의 기기 ID·앱 해시는 보고서에 보관합니다. 지원 표에 앱 비밀이나 canary 값을 복제하지 않습니다. 테스트 장치와 앱을 바꾸면 새 기기 증거로 다시 검사하십시오. CVE는 관찰한 OS/패치·실제 빌드 의존성과 공개된 공식 인텔을 대조하며 `version-affected`도 exploit 재현을 뜻하지 않습니다. 공개 전 제로데이 발견·즉시 전달·OWASP MASVS 인증·전체 MASTG 통과를 주장하지 않습니다.

기본 후보 탐지는 `candidate`, 설정 증거는 `configuration-confirmed`, 해당 런타임 증거는 `runtime-confirmed`로 구분합니다. 규칙 coverage와 경고가 실제 검사 범위를 나타내며 결과가 없다는 이유만으로 앱 전체를 안전하다고 선언하지 않습니다.

공식 도구 고정 근거: [checkout v7.0.0](https://github.com/actions/checkout/releases/tag/v7.0.0), [setup-uv v10.2.0](https://github.com/astral-sh/setup-uv/releases/tag/v10.2.0), [setup-uv Python 설치 안내](https://github.com/astral-sh/setup-uv/blob/v10.2.0/README.md#python-version). 설치·검증 절차와 재현성 한계는 [OPERATIONS.md](OPERATIONS.md)에 설명합니다.

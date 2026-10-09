# Analysis extension (APSA 1.2)

English is the source of truth for this document. These changes were developed
on the `hardening/real-app-cve-v1` branch and ship in APSA 1.2.0. They are not
part of APSA 1.1.0 or earlier packages.

The extension adds bounded AAB input, embedded IPA metadata, Objective-C
candidates and parser OS isolation. It also recovers selected Swift/Kotlin
grammar gaps and streams literal Xcode plist references across larger project
files. Adapted source files retain original byte offsets and source line
coordinates and remain partial; unsupported syntax still leaves explicit gaps.
Referenced plists are observed only when the bounded input actually contains
them. Their path, declaration line and unavailable state remain in the inventory.

| Input or boundary | Implemented scope | Remaining limits |
| --- | --- | --- |
| AAB | AAPT2 protobuf base manifest; module inventory; bounded DEX calls with module paths | Resource and feature-manifest merging, device targeting and installed split sets are unverified. Every bundle audit stays partial. AAB does not run the legacy APK signing/ELF lint engine. |
| IPA | Main executable plus declared framework, extension, nested app and Frameworks dylib Mach-O metadata | Separate hashes and bundle roles; embedded identity cannot replace the main app. No signature authentication or native instruction/control-flow analysis. Encrypted and malformed inputs retain warnings and unavailable scope. |
| Objective-C `.m` | CST calls to imported CommonCrypto weak digests; straight-line declared WKNavigationAction → NSURLRequest → WKWebView flow | Candidate evidence only, always partial. No macro evaluation, dynamic dispatch, swizzling, interprocedural validation, Objective-C++ `.mm` or complete callable inventory. |
| Parser OS permissions | Parent stages bounded source/configuration bytes through stable directory/file descriptors, then system Seatbelt on macOS or bubblewrap on Linux grants staged input/SBOM and trusted runtime read-only access, fresh scratch read/write and no host network | Trusted runtime/system libraries are readable; macOS file metadata and exact parent-directory listings are visible. This isolates the parser process, not the parent CLI, MCP client, installation or device commands. |

`APSA_PARSER_SANDBOX=auto` is the default. Before parsing, the parser modules
and native extensions load without any input under the exact policy. If the system backend is absent or
this activation probe fails (for example inside another Seatbelt sandbox or
with blocked Linux user namespaces), the report explicitly records
`unavailable`, the attempted backend and the probe reason in
`inventory.parser_isolation` and `inventory.warnings`, and parses with resource
limits only. Set `APSA_PARSER_SANDBOX=required` to refuse such an
audit, or `off` to request resource limits alone. Once the parser itself has
launched under isolation, a failure aborts the audit; there is no unsandboxed
retry. macOS framework Python builds may execute only their exact app-bundle
interpreter. `doctor` reports availability, while
`inventory.parser_isolation` records successful worker enforcement. The parser
receives a minimal environment; report stores are excluded before staging and
overlapping runtime mounts are masked. The original app path is never a Linux
bind source. Changed root identity aborts the audit; unreadable/oversized source
omissions retain incomplete coverage. Staging has byte/file/depth/entry/time
budgets and fails explicitly on budget exhaustion. A directory snapshot is not
an atomic build snapshot across every file; scan a stable build for that assurance.
CPU/RSS/time/output limits remain separate controls.

Parser stdin is closed and unrelated descriptors are not inherited. Standard
output/error are bounded pipes. macOS permits literal root/runtime-parent and
staged file-input parent directory listings for loader/import/descriptor
initialization, without recursive sibling content access. Fresh scratch is
readable and writable; executable mappings
are limited to trusted runtime/system code and the system OpenSSL helper.

Gradle version catalog entries retain their declared names and versions with
unresolved usage. An alias merely present in the catalog cannot establish a
shipped dependency or satisfy exact CVE correlation; supply resolved build/SBOM
evidence. DEX under an AAB module without a manifest path is skipped with partial
coverage and listed separately.

Validation uses new synthetic malformed/positive/negative fixtures, a fresh
AAPT2-generated protobuf manifest, and disposable runner denial probes for
unrelated reads, input writes, report-store access and host networking. Existing
user files and runtime history are excluded. macOS permits the trusted Python
executable and system OpenSSL helper; Linux exposes trusted system executables
within the isolated namespace, without host-network access.

The original six-app evaluation and its captured OSV responses stay frozen.
Replaying them measures development regression after their labels were seen.
A separate pre-scan labeled holdout uses two other public source snapshots and
three Apple CVEs with actual captured official bulletin bytes. Selected source
facts and published version boundaries do not establish app exploitability,
installed patch safety, comprehensive production accuracy or OWASP certification.
The VLC repository-search absence claim is provisional and unscored; the full
pinned archive independently records any checked-in Info.plist paths.

# 분석 확장 (APSA 1.2)

영어가 원본이며 이 절은 번역입니다. 변경은 `hardening/real-app-cve-v1`
브랜치에서 개발했고 APSA 1.2.0에 포함됩니다. APSA 1.1.0 이하 패키지에는
포함되지 않습니다.

AAB 입력, IPA 내장 바이너리 메타데이터, Objective-C 후보와 파서 OS 격리를
추가했습니다. 일부 Swift·Kotlin 구문 누락을 복구하고 큰 Xcode 프로젝트에서
리터럴 plist 참조를 읽습니다. 호환 처리한 소스는 원본 바이트 오프셋·행 번호를
유지하며 부분 분석으로 남습니다. 참조된 plist가 실제 입력에 없으면 검사하지
않고 참조 위치·선언 행·미확인 상태를 기록합니다.

| 입력·경계 | 구현 범위 | 남은 한계 |
| --- | --- | --- |
| AAB | AAPT2 protobuf base 매니페스트, 모듈 목록, 모듈 경로가 포함된 제한된 DEX 호출 | 리소스·feature 매니페스트 병합, 기기 targeting, 설치된 split은 미확인. 항상 부분 감사이며 기존 APK 서명·ELF lint 엔진은 실행하지 않음 |
| IPA | 메인 실행 파일과 선언된 framework·확장·중첩 앱·Frameworks dylib의 Mach-O 메타데이터 | 해시·역할을 분리하며 메인 앱 식별자를 대체하지 않음. 서명 인증·native 코드 흐름 미지원. 암호화·손상 입력의 누락 범위를 표시 |
| Objective-C `.m` | CommonCrypto 약한 해시 호출, 선언된 WKNavigationAction → NSURLRequest → WKWebView의 직선 흐름 | 후보·부분 분석만 제공. 매크로, 동적 dispatch, swizzling, 함수 간 검증, `.mm`, 전체 함수 목록 미지원 |
| 파서 OS 권한 | 부모가 안정된 파일·디렉터리 descriptor로 소스·설정을 제한해 복사한 뒤 macOS Seatbelt·Linux bubblewrap으로 복사 입력·SBOM·신뢰 런타임 읽기, 새 scratch 읽기·쓰기, 호스트 네트워크 거부 | 신뢰 런타임·시스템 라이브러리, macOS 파일 메타데이터·지정한 부모 폴더 자체의 목록은 접근 가능. 부모 CLI·MCP·설치·기기 명령의 격리가 아님 |

기본값 `APSA_PARSER_SANDBOX=auto`는 파싱 전에 입력 없이 파서 모듈과 native
확장을 같은 정책으로 불러와 봅니다. 시스템 백엔드가 없거나 이 활성화 검사가 실패하면(예: 다른
Seatbelt sandbox 내부, Linux user namespace 차단) `unavailable`, 시도한 백엔드와
실패 이유를 기록하고 자원 제한만 적용합니다. `required`는 OS 격리가 불가능하면
감사를 거부하고, `off`는 자원 제한만 요청합니다. 파서가 격리 상태로 시작된 뒤 실패하면
감사는 중단하며 격리 없는 재시도는 없습니다. macOS framework Python은 정확한
app-bundle 인터프리터만 실행할 수 있습니다. `doctor`는 가용성, `inventory.parser_isolation`은 성공한 worker의
실제 적용 상태를 나타냅니다. 파서는 최소 환경 변수만 받고 보고서 저장소는
복사 전 제외하며 런타임 마운트와 겹치면 가립니다. 원본 앱 경로는 Linux bind
원본으로 쓰지 않습니다. 루트 식별자 변경은 감사를 거부하고 읽기 실패·초과
소스 누락은 불완전 범위를 남깁니다. 복사에는 바이트·파일·깊이·항목·시간 제한이
있으며 한도 초과는 실패합니다. 여러 파일의 복사는 원자적 빌드 스냅샷이 아니므로
그 보장이 필요하면 안정된 빌드를 검사하세요. CPU·RSS·시간·출력 제한은 별도로
유지합니다.

파서의 표준입력은 닫고 무관한 descriptor는 상속하지 않습니다. 표준출력·오류는
크기가 제한된 pipe입니다. macOS loader·import 초기화를 위해 루트·런타임 부모
폴더·복사한 입력 파일의 부모 폴더 자체의 목록만 허용하며, 형제 파일 내용을
재귀적으로 읽게 하지 않습니다.
새 scratch는 읽기·쓰기를 허용하고 실행 파일 매핑은 신뢰 런타임·시스템과
OpenSSL에 한정합니다.

Gradle catalog의 이름·버전은 사용 여부 미확인으로 보존합니다. catalog에만 있는
alias는 포함된 의존성·정확한 CVE 매칭을 증명하지 못하므로 실제 빌드·SBOM 근거가
필요합니다. 매니페스트 경로가 없는 AAB 모듈의 DEX는 건너뛰고 부분 범위와 별도
목록을 남깁니다.

새 합성 양성·음성·손상 입력, AAPT2 생성 protobuf, 일회용 CI의 파일·네트워크
거부 검사로 검증합니다. 기존 사용자 데이터·이력은 제외합니다. macOS에서는
신뢰 Python과 시스템 OpenSSL, Linux에서는 격리된 namespace의 신뢰 시스템
실행 파일을 허용하되 호스트 네트워크에 접근하지 못합니다.

기존 6개 앱·OSV 응답은 고정된 채 개발 회귀 검사로 재생합니다. 별도의 독립
정답 평가는 새 공개 소스 2개와 Apple CVE 3개를 실제 공식 공지로 대조합니다.
선택한 소스 사실·공개 버전 경계는 앱 악용 가능성, 설치 패치 안전성, 운영 탐지율,
OWASP 인증을 증명하지 않습니다. VLC 검색의 plist 부재 주장은 임시 근거로
채점하지 않으며, 고정된 전체 소스에서 실제 Info.plist 경로를 따로 확인합니다.

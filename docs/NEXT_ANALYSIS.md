# Analysis extension (APSA 1.2, 1.3 and 1.5)

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
and native extensions that the parent can find load without any input under
the exact policy and parser resource limits. If the system backend is absent,
the report records `unavailable` and parses with resource limits only. If the
backend is present but this activation probe fails (for example inside another
Seatbelt sandbox or with blocked Linux user namespaces), the report also records
the attempted backend and probe reason in `inventory.parser_isolation` and adds
an `inventory.warnings` entry. Set `APSA_PARSER_SANDBOX=required` to refuse such an
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
evidence. Unreleased development work links aliases to the configurations that
use them and reads Gradle lockfiles; see
[dependency evidence results](../benchmarks/DEPENDENCY_RESULTS.md). DEX under an AAB module without a manifest path is skipped with partial
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

## APSA 1.3.0 additions

These changes were developed on `dev/evidence-depth` after APSA 1.2.0 and ship
in APSA 1.3.0. They are not part of APSA 1.2.0 or earlier packages.

- **Gradle dependency evidence.** Catalog aliases used in shipped configurations
  become declared candidates; application-module lockfiles give exact
  coordinates. See [DEPENDENCY_RESULTS.md](../benchmarks/DEPENDENCY_RESULTS.md).
- **Parser adaptations.** Byte-preserving adaptations cover Swift
  `@_documentation(visibility:)`, `#warning`/`#error`, empty-tuple values and
  token-level `nonisolated(unsafe)`, and Objective-C `typedef NS_ENUM`-family
  macros, `comment:` labels in `NSLocalizedString` and one kept branch per
  preprocessor conditional (conditional imports are removed, a literal `#if 0`
  keeps its alternative). Adapted files stay partial, and an Objective-C
  function overlapping a normalized conditional is skipped as uncertain because a
  guard may sit in a dropped branch. On the already analyzed
  VLC iOS and Firefox iOS sources, files with remaining errors drop from 22 to
  0 and from 66 to 7. On two fresh repositories measured once without tuning,
  the adaptations recover 83 of 223 Signal-iOS Swift error files (1.2.0: 2),
  39 of 98 WordPress-iOS Swift files (1.2.0: 1) and 4 of 11 WordPress-iOS
  Objective-C files (1.2.0: 0); Signal-iOS Objective-C remains 0 of 32, mainly
  `NS_ASSUME_NONNULL_BEGIN` (measured once; see
  `benchmarks/results/2026-10-09-parser-fresh-repos.json`).
- **AAB feature modules.** Each non-base module's protobuf manifest is decoded;
  its components and deep links carry the module name and declared delivery
  (install-time, on-demand, fast-follow). App identity and application flags
  still come only from the base manifest; installation state stays unknown.
- **Mach-O code integrity.** CodeDirectory page hashes and entitlement-slot
  hashes are recomputed. Mismatch is reported as modified with a warning,
  except mismatches confined to an encrypted region, which stay unverifiable.
  The CMS signature, certificate chain, team and provisioning are not
  authenticated; `signature_verified` stays false. Encrypted (App Store) or
  unsigned executables leave `BINARY-IOS-CODE-INTEGRITY` `not-run`, and a
  malformed or oversized CodeDirectory is unverifiable rather than a failure.
  Scatter vectors are not modeled, and whether CodeDirectory 0x20500
  `preEncryptOffset` changes encrypted-page semantics is still to be checked
  against xnu; until then encrypted pages stay unverifiable.
- **Android bulletin history and chipsets.** `apsa intel backfill --source
  android --since YYYY-MM [--until YYYY-MM]` fetches an explicit, bounded month
  range. Bulletin records keep a vendor scope. Device observation adds the SoC
  manufacturer and vendor security patch level (also accepted from
  `--device-info`); chipset and kernel components use the older of the
  platform and vendor patch levels, because GKI kernel updates vary.
  A SoC vendor match or mismatch is recorded in `chipset_vendor` beside the
  patch-level state and never replaces it, because connectivity chips can come
  from other vendors. Apple
  history, Pixel/OEM/chipset vendor bulletins and amended-entry tracking are
  not backfilled.
- **Independent source pairs.** See [FPFN_RESULTS.md](../benchmarks/FPFN_RESULTS.md).
- **Device evidence.** No physical device was used; see
  [DEVICE_EVIDENCE.md](DEVICE_EVIDENCE.md) for what approved evidence requires.

Compatibility and privacy notes:

- `scan --online` and `intel watch --online` send catalog aliases used in
  shipped configurations and the release-runtime lockfile coordinates of every
  module (application coordinates exact, others declared candidates), including
  transitive coordinates and private group IDs, to OSV; there is no exclusion
  list. The budget stays at 100 package queries per run, as in 1.2.0.
  Unresolved or unsupported entries use no budget. Packages without an OSV
  result from the last day go first; among them, packages declared in build
  files (including declarations a lockfile superseded) precede lockfile
  coordinates in lockfile order. A typical application lockfile (179-412
  shipped coordinates measured) exceeds one run's budget, so the remaining
  packages stay `not-run`, the warning states how many, a required
  `DEPENDENCY-CVE` rule cannot pass and the online audit is incomplete (exit 3
  under the default `fail_on_partial` policy). Repeated runs within a day
  advance through the remainder; a package with an OSV result from the last day
  counts as checked. Unresolved aliases and unsupported ecosystems remain online
  errors on every run and keep the audit incomplete. Batch querying would change the
  recorded per-package OSV request format that the frozen replay depends on,
  so it is later work together with an exclusion control.
- Lockfile matches are exact and therefore `version-affected`; the default
  policy fails on high and critical ones. Their finding identity includes the
  lockfile path, so `only_new` baselines treat them as new and waivers for the
  earlier declared finding no longer match.
- An unrecognized `gradle.lockfile` line (for example a merge-conflict marker)
  marks the inventory partial, which exits 3 under the default policy, and
  `*.lockfile` files count toward the source read budget.
- APSA does not check that dependency locking is enabled or that a lockfile is
  current. All release runtime classpaths of every application module are
  merged (flavors and wear, TV or automotive apps). `--source-module` scans
  only that directory, leaving a root catalog and library-module declarations
  unread.
- Consistent CodeDirectory hashes do not prove authenticity: a modified binary
  that was re-signed is consistent. A mismatch is a warning, not a finding.
- `intel sync` refreshes only the recent Android bulletin window; older months
  need `intel backfill`. Records cached by 1.2.0 derive their vendor scope from
  the component name; entries outside chipset and kernel sections are evaluated
  on the platform patch level only. Without a valid `vendor_security_patch`
  (YYYY-MM-DD), chipset and kernel entries are also compared on the platform
  level, and the advisory basis says so.

Release evaluation: every harness (dependency oracle comparison, frozen
replay, independent source pairs, competitive comparison, public real-world
sources, next holdout and generated AAB) was re-run on the frozen release
runtime; see `RELEASE_READINESS.md` for runs and results.


## APSA 1.5.0 additions

1.5.0 was developed on `dev/detection` after 1.4.0. It adds source checks for the
OWASP MASWE weaknesses behind most OWASP MASTG demo misses. Every new finding is
a candidate except configuration evidence, and each rule's catalog `scope`
states what it reads.

- **Cryptography.** Framework `Cipher.getInstance` with DES, 3DES, RC4, RC2 or
  Blowfish, or a bare `"AES"` whose provider default is ECB; CommonCrypto
  broken algorithms and ECB options; CryptoKit `Insecure.MD5` and
  `Insecure.SHA1`; RSA key sizes below 2048 bits. Key and IV material counts as
  constant when it is a literal, a literal array, a `BuildConfig` field, an
  immutable literal-initialized constant of the same file, or a conversion or
  decoder of those. A local passed to another call, written element by element,
  or named inside a closure that is not followed is treated as filled at
  runtime, and zero-filled fields are never constants.
- **Local authentication.** `BiometricPrompt` and `FingerprintManager` calls
  without a CryptoObject (by argument count), `LAContext.evaluatePolicy` in a
  file without a Keychain access control, device-credential fallback, and keys
  or access controls that survive new biometric enrollment. A file with a
  time-bound Keystore key that requires authentication counts as bound. Whether
  the protected operation is sensitive is not decided.
- **Transport.** TLS versions below 1.2 requested in code, Network.framework
  plain TCP/UDP, BSD sockets and CFStream (outside ATS), and the network security
  configuration referenced by the selected manifest: user CAs and cleartext,
  outside debug-overrides and debug or test source sets. The configuration is
  read from `<module>res/xml` or `<module>src/<set>/res/xml`, or beside the
  manifest when the module has none. Several source-set variants make the
  findings candidates. Unparsable text XML, a missing referenced file or a
  build placeholder is partial; compiled AAB resources and unresolved compiled
  references are not-run. A parsed configuration overrides the manifest's
  `usesCleartextTraffic` on Android 7+ when it states cleartext or targets 28+.
- **Platform.** App Links without `autoVerify`, Intents taken from another
  Intent's extras and launched (unless a line compares the nested Intent's
  component or package), and implicit Intents with an action in the source
  file's package namespace sent to activities or broadcasts without a permission.
  Implicit service Intents are not reported; they throw on API 21+.
- **Untrusted data.** Path traversal from Intent data and extras, exported
  provider arguments, provider display names, archive entry names and URL query
  items into `File`, file streams, `RandomAccessFile`, `appendingPathComponent`,
  `appending(path:)` and `URL(fileURLWithPath:)`. File descriptors and
  `Context.openFileOutput` are not paths. `File(x).name`, `lastPathComponent` and
  `substringAfterLast("/")` reduce input to a file name. A canonical-path prefix
  comparison or a containment test for `".."` anywhere in the function
  suppresses the result; neither is tied to the tainted variable, and
  `replace("..", ...)` is not a check. Keyed unarchiving without secure coding
  is a separate pattern rule.
- **WebView.** Safe Browsing turned off in code or in the manifest meta-data
  (source trees only), UIWebView, and WKWebView file-URL access through private
  preferences or `loadFileURL` read access to a whole app directory.
- **Analyzer model.** Kotlin `let`, `also`, `use`, `apply`, `run` and `with`
  lambdas are followed as blocks; a `?.` call or a lambda with `return@` merges
  like a branch that may not run. Other lambdas and Swift closures are still not
  analyzed. Locals created with an imported class's constructor carry that type.
  Guards are recognized by text in the same function, not by dominance.
  Per-function and per-file budgets bound the cost; a check that reaches its
  match budget reports partial coverage.
- **Evaluation.** [OWASP MASTG demos](../benchmarks/MASTG_RESULTS.md) (a
  development rerun: 52 of 78 in-scope failing demos, one false positive) and the
  [blind MASWE-labeled pairs](../benchmarks/BLIND_PAIRS_RESULTS.md) (first run:
  7 of 21 in-scope pairs at the labeled lines). Known gaps: flow across
  functions, controls that were never added, inputs above the 64 MB text
  staging budget (refused), and very large functions with many branches or
  PendingIntent calls, which are slow but bounded.

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
확장 중 부모가 찾은 것을 같은 정책과 파서 자원 제한 아래에서 불러와 봅니다. 시스템 백엔드가
없으면 `unavailable`을 기록하고 자원 제한만 적용합니다. 백엔드가 있지만 이 활성화 검사가
실패하면(예: 다른 Seatbelt sandbox 내부, Linux user namespace 차단) 시도한 백엔드와 실패
이유를 `inventory.parser_isolation`에 기록하고 `inventory.warnings` 항목을 추가합니다. `required`는 OS 격리가 불가능하면
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
필요합니다. APSA 1.3.0은 alias를 사용하는 구성과 연결하고 Gradle lockfile을
읽습니다(아래 1.3.0 절). [의존성 근거 결과](../benchmarks/DEPENDENCY_RESULTS.ko.md)를 참고하세요. 매니페스트 경로가 없는 AAB 모듈의 DEX는 건너뛰고 부분 범위와 별도
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

## APSA 1.3.0 추가 사항

영어 원본의 "APSA 1.3.0 additions" 절을 요약한 번역입니다. 이 변경은 1.2.0 이후
`dev/evidence-depth`에서 개발했고 APSA 1.3.0에 포함됩니다.

- **Gradle 의존성 근거.** 출하 구성에서 쓰는 catalog alias는 `declared` 후보가 되고,
  application 모듈 lockfile은 정확한 좌표를 제공합니다. library 모듈 lockfile은 앱
  근거가 아니며, 모든 출하 앱이 해결한 선언 후보만 대체합니다. 부분 입력·해석하지 못한
  project 참조에서는 대체하지 않습니다.
- **파서 호환.** Swift `@_documentation(visibility:)`, `#warning`/`#error`, 빈 튜플,
  토큰 단위 `nonisolated(unsafe)`와 Objective-C `NS_ENUM` 계열 매크로,
  `NSLocalizedString`의 `comment:` 라벨, 전처리 조건부의 한 가지 분기를 바이트 위치를
  유지한 채 처리합니다. 호환 처리한 파일은 부분 분석이며, 정규화한 조건부와 겹치는
  Objective-C 함수는 불확실로 제외합니다.
- **AAB feature 모듈.** base가 아닌 모듈의 protobuf 매니페스트를 해석해 컴포넌트·딥링크에
  모듈 이름과 선언된 전달 방식을 붙입니다. 앱 식별자·application 플래그는 base에서만
  가져오며 설치 상태는 알 수 없습니다.
- **Mach-O 코드 무결성.** CodeDirectory 페이지·entitlement 슬롯 해시를 다시 계산합니다.
  불일치는 modified와 경고로 보고하되, 암호화 구간에 한정된 불일치는 검증 불가로 둡니다.
  CMS 서명·인증서 체인·팀·provisioning은 인증하지 않으며 `signature_verified`는 false입니다.
- **Android 공지 이력과 칩셋.** `apsa intel backfill --source android --since YYYY-MM`은
  명시한 기간만 수집합니다. 칩셋·커널 항목은 플랫폼과 vendor 패치 수준 중 오래된 쪽을 쓰며,
  `chipset_vendor` 일치·불일치는 패치 수준 상태를 대체하지 않습니다. Apple 이력과
  Pixel/OEM/칩셋 vendor 공지는 소급하지 않습니다.
- **호환성·개인정보.** `--online`은 catalog alias와 모든 모듈 lockfile의 release runtime
  좌표(전이 좌표·비공개 group ID 포함)를 OSV에 보내며 제외 목록은 없습니다. OSV 조회는
  1.2.0과 같이 실행당 최대 100개이고 미확인·미지원 항목은 한도를 쓰지 않습니다. 최근 하루 안의
  OSV 결과가 없는 패키지를 먼저, 그중 빌드 파일에 선언된 패키지(lockfile로 대체된 선언 포함)를
  lockfile 좌표보다 먼저 조회합니다. 한 번의 실행으로 남은 패키지는 `not-run`이며 경고에 개수를
  표시하고, 필수 `DEPENDENCY-CVE` 규칙은 통과할 수 없으며 온라인 감사는 불완전합니다. 하루 안에
  반복 실행하면 남은 패키지를 이어서 조회하지만, 미확인 alias·미지원 생태계는 매번 오류로 남아
  감사를 불완전하게 유지합니다.
- **기준선·lockfile 전제.** lockfile 대조 결과는 위치가 바뀌어 `only_new`에서 새 항목이 되고
  이전 예외와 일치하지 않습니다. APSA는 dependency locking 활성화·lockfile 최신 여부를 확인하지
  않으며 모든 application 모듈의 release runtime classpath를 합칩니다. `--source-module`은 그
  폴더만 검사합니다.
- **무결성·공지.** CodeDirectory 해시 일치는 진위를 증명하지 않으며(재서명된 수정 바이너리도
  일치), 불일치는 발견 항목이 아닌 경고입니다. `intel sync`는 최근 공지만 갱신하고, 1.2.0이
  캐시한 공지는 컴포넌트 이름에서 vendor 범위를 도출합니다.
  실기기는 사용하지 않았습니다([DEVICE_EVIDENCE.md](DEVICE_EVIDENCE.md)).

## APSA 1.5.0 추가 사항

영어 원본의 "APSA 1.5.0 additions" 절을 요약한 번역입니다. 1.4.0 이후 `dev/detection`에서 개발했습니다.

- **암호.** DES·3DES·RC4·RC2·Blowfish를 고르거나 provider 기본값이 ECB인 `"AES"`만 쓴 `Cipher.getInstance`,
  CommonCrypto의 깨진 알고리즘과 ECB 옵션, CryptoKit `Insecure.MD5`·`Insecure.SHA1`, 2048비트 미만 RSA
  키를 봅니다. 키와 IV 재료는 리터럴, 리터럴 배열, `BuildConfig` 필드, 같은 파일의 불변 리터럴 상수, 또는 그
  변환·디코딩일 때 상수로 봅니다. 다른 호출에 넘기거나 원소를 쓰거나 따라가지 않는 클로저에서 이름이 나온
  지역 값은 런타임에 채운 것으로 보며, 0으로 채운 필드는 상수가 아닙니다.
- **로컬 인증.** CryptoObject 없는 `BiometricPrompt`·`FingerprintManager` 호출(인자 개수 기준), Keychain
  access control이 없는 파일의 `LAContext.evaluatePolicy`, 기기 비밀번호 대체 허용, 새 생체 등록 뒤에도
  유지되는 키·access control을 봅니다. 인증을 요구하는 시간 제한 Keystore 키가 있는 파일은 결합된 것으로
  봅니다. 보호하는 작업이 민감한지는 판단하지 않습니다.
- **통신.** 코드에서 요청한 TLS 1.2 미만, ATS 밖의 Network.framework 평문 TCP/UDP·BSD 소켓·CFStream, 선택한
  매니페스트가 참조하는 네트워크 보안 설정의 사용자 CA와 cleartext(debug-overrides, debug·test 소스셋 제외)를
  봅니다. 설정은 `<module>res/xml` 또는 `<module>src/<set>/res/xml`에서, 없으면 매니페스트 옆에서 읽습니다.
  소스셋 변형이 여러 개면 후보로 낮춥니다. 해석할 수 없는 텍스트 XML, 없는 참조 파일, 빌드 placeholder는
  partial이고, 컴파일된 AAB 리소스와 해석되지 않은 컴파일 참조는 not-run입니다. 해석한 설정이 cleartext를
  명시하거나 target 28 이상이면 Android 7+에서 매니페스트 `usesCleartextTraffic`를 대신합니다.
- **플랫폼.** `autoVerify` 없는 App Links, 다른 Intent의 extra에서 꺼내 실행하는 Intent(중첩 Intent의
  component·package를 비교하는 줄이 없을 때), 소스 파일 패키지 네임스페이스의 action을 쓰는 암시적 Intent를
  권한 없이 액티비티·브로드캐스트로 보내는 경우를 봅니다. 암시적 서비스 Intent는 API 21+에서 예외가 나므로
  보고하지 않습니다.
- **신뢰할 수 없는 데이터.** Intent data·extra, 외부 노출 provider 인자, provider 표시 이름, 압축 항목 이름,
  URL query item이 `File`, 파일 스트림, `RandomAccessFile`, `appendingPathComponent`, `appending(path:)`,
  `URL(fileURLWithPath:)`에 닿는 경로 조작을 봅니다. 파일 디스크립터와 `Context.openFileOutput`은 경로가
  아닙니다. `File(x).name`, `lastPathComponent`, `substringAfterLast("/")`는 입력을 파일 이름으로 줄입니다.
  함수 안 어디든 canonical 경로 접두사 비교나 `".."` 포함 검사가 있으면 결과를 내지 않으며, 둘 다 오염된
  변수와 연결하지 않습니다. `replace("..", ...)`는 검사로 보지 않습니다. secure coding 없는 keyed
  unarchiving은 별도 패턴 규칙입니다.
- **WebView.** 코드나 매니페스트 meta-data(소스 트리만)에서 끈 Safe Browsing, UIWebView, private
  preference나 앱 디렉터리 전체에 대한 `loadFileURL` 읽기 권한으로 허용한 WKWebView 파일 URL 접근을 봅니다.
- **분석 모델.** Kotlin `let`·`also`·`use`·`apply`·`run`·`with` 람다를 블록으로 따라가며, `?.` 호출이나
  `return@`이 있는 람다는 실행되지 않을 수도 있는 분기처럼 병합합니다. 다른 람다와 Swift 클로저는 여전히
  분석하지 않습니다. import한 클래스의 생성자로 만든 지역 값은 그 타입을 가집니다. 가드는 같은 함수의
  텍스트로 인식하며 지배 관계는 보지 않습니다. 함수·파일 단위 예산이 비용을 제한하고, 일치 예산에 걸린
  검사는 partial입니다.
- **평가.** [OWASP MASTG 데모](../benchmarks/MASTG_RESULTS.ko.md)(개발 재실행: 평가 대상 실패 데모 78개 중
  52개, FP 1개)와 [blind MASWE 라벨 쌍](../benchmarks/BLIND_PAIRS_RESULTS.ko.md)(첫 실행: 평가 대상 21쌍 중
  7쌍을 라벨 줄에서 탐지). 알려진 한계는 함수 간 흐름, 추가된 적 없는 통제, 64MB 텍스트 스테이징 한도를
  넘는 입력(거부), 분기나 PendingIntent 호출이 매우 많은 큰 함수(느리지만 제한됨)입니다.

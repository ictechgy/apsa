# APSA (앱사)

**근거 중심의 Android·iOS 보안 감사 도구.**

[English](https://github.com/ictechgy/apsa/blob/main/README.md) · [한국어](https://github.com/ictechgy/apsa/blob/main/README.ko.md)

영문 README가 원본입니다. 이 문서는 영문 원본을 기준으로 작성한 한국어 번역입니다.

APSA는 개발자와 보안팀이 자기 모바일 앱을 감사하는 도구입니다. 소스 코드와 APK·AAB·IPA 빌드를 검사하고, 공개 취약점 정보를 대조하며, 근거·검사 범위·보고서 이력을 함께 관리합니다. CLI, 터미널 UI, MCP, 재사용 가능한 스킬에서 같은 감사 엔진을 사용합니다.

영어 발음은 **“ap-sah”**, 한글 이름은 **앱사**입니다. “앱 + 감사”를 연결한 이름이며 **App Security Audit**라는 의미도 담았습니다. 기존 Quaygate 린트 엔진과 Mobile Audit 작업 흐름을 한 패키지에 통합했습니다.

APSA 1.1은 모델 보고서의 제한된 페이지 조회, 승인된 휴대형 기준선, 정책 판정 내보내기, 소스 모듈·설정 선택을 제공합니다. 계약과 예제는 영문 원본 [모델·팀 워크플로](docs/MODEL_WORKFLOWS.md), 이후 분석 단계는 [릴리스 순서](docs/ROADMAP.md)를 참고하십시오.

미지원 언어가 혼합된 소스와 잘린 패턴 결과는 불완전 검사로 표시합니다. Gradle 선언 버전은 실제 빌드에서 확인되기 전까지 후보이며, OS-CVE는 최근 공지 범위만 대조하므로 피드가 최신이어도 역사적 커버리지를 충족하지 않습니다.

APSA 1.2는 AAB base 매니페스트·모듈 DEX 분석, IPA 내장 Mach-O 메타데이터,
제한된 Objective-C `.m` 후보와 실행 가능한 환경에서 기본으로 켜지는 파서 OS 격리를 추가합니다. AAB 감사는
항상 부분 감사이며, IPA 내장 메타데이터는 서명 진위를 인증하지 않습니다.
[분석 범위와 한계](https://github.com/ictechgy/apsa/blob/main/docs/NEXT_ANALYSIS.md)와 [독립 holdout 결과](https://github.com/ictechgy/apsa/blob/main/benchmarks/NEXT_RESULTS.ko.md)를
참고하세요.

**1.1에서 업그레이드할 때.** 기본값 `APSA_PARSER_SANDBOX=auto`는 입력 없이 실행하는
활성화 검사가 성공하면 파서를 macOS Seatbelt 또는 Linux bubblewrap 아래에서
실행합니다. 백엔드가 없으면 보고서에 `parser_isolation.state: unavailable`을 기록하고
자원 제한만으로 파싱합니다. 백엔드가 있지만 시작하지 못하면(예: 다른 sandbox 내부,
user namespace 차단) 시도한 백엔드와 실패 이유를 함께 기록하고 inventory 경고를 추가합니다. `required`는 이런 감사를 거부하고 `off`는 백엔드를 사용하지 않습니다.
격리가 시작된 뒤의 파서 실패는 격리 없이 재시도하지 않고 감사를 중단합니다. Gradle
version catalog에만 선언된 의존성은 빌드 사용 근거나 해결 버전을 제공하기 전까지 CVE를
대조하지 않습니다. 새 규칙(`AST-CRYPTO-ECB`, `AST-CRYPTO-WEAK-HASH`, `AST-SQL-CONCAT`,
`OBJC-CRYPTO-WEAK-HASH`, `OBJC-WEBVIEW-UNTRUSTED-REQUEST`)은 기존 1.1 기준선 대비
새 발견 항목을 추가할 수 있습니다.

APSA 1.3은 Gradle version catalog alias를 실제로 사용하는 출하 의존성 구성과
연결하고, application 모듈의 `gradle.lockfile` 좌표를 해결된 버전으로 읽습니다.
AAB feature 모듈 매니페스트를 해석하고, 서명을 인증하지 않은 채 Mach-O
CodeDirectory의 페이지·entitlement 해시를 다시 계산하며, 더 많은 Swift·Objective-C
구문을 호환 처리합니다. 지정한 기간의 Android 보안 공지를 SoC 제조사·vendor 패치
수준 정보와 함께 소급 수집할 수 있습니다.
[의존성 근거 결과](https://github.com/ictechgy/apsa/blob/main/benchmarks/DEPENDENCY_RESULTS.ko.md),
[독립 취약·수정 소스 쌍](https://github.com/ictechgy/apsa/blob/main/benchmarks/FPFN_RESULTS.ko.md),
[분석 범위와 한계](https://github.com/ictechgy/apsa/blob/main/docs/NEXT_ANALYSIS.md)를 참고하세요.

**1.2에서 업그레이드할 때.**

- 출하 구성에서 참조하는 catalog alias는 `declared` 후보가 되어 다시 CVE를 대조할 수
  있습니다. 참조되지 않거나 테스트·빌드 도구용인 alias는 미확인으로 남습니다.
  application 모듈 lockfile 좌표는 정확한 버전이므로 대조 결과가 `version-affected`가
  되며, 기본 정책은 high·critical 항목에서 실패합니다. 다른 모듈의 lockfile 좌표는
  `declared` 후보로 남습니다. 모든 출하 앱이 해결한 선언 후보는 대체(superseded)되어 CVE
  대조에서 빠집니다. 부분 입력에서는 모든 후보를 유지하며, 해석하지 못한 project 참조가
  있으면 application 자신의 선언만 대체될 수 있습니다.
- lockfile 전제: APSA는 dependency locking 활성화나 lockfile 최신 여부를 확인하지 않으며,
  모든 application 모듈(flavor, wear·TV·automotive 앱 포함)의 release runtime classpath를
  합칩니다. `--source-module`은 해당 모듈 폴더만 검사하므로 그 밖의 루트 version catalog와
  library 모듈 선언은 읽지 않습니다.
- 기준선·예외: lockfile로 해결된 발견 항목은 위치(`gradle.lockfile`)와 상태가 바뀌므로
  `only_new`는 새 항목으로 보고, 이전 발견 ID에 대한 예외는 더 이상 일치하지 않습니다.
  업그레이드 후 기준선을 다시 승인하세요.
- `--online`은 출하 구성에서 쓰는 catalog alias와 모든 모듈 lockfile의 release runtime
  좌표(전이 좌표·비공개 group ID 포함)를 OSV에 보내며 제외 목록은 없습니다. 한 번에 최대
  100개 패키지를 조회하며, 최근 하루 안의 OSV 결과가 없는 패키지를 먼저, 그중에서는 빌드
  파일 선언을 lockfile 좌표보다 먼저 조회합니다. 측정한 application lockfile은 출하 좌표가
  179~412개였으므로 한 번의 실행으로는 나머지가 `not-run`으로 남아, 필수 `DEPENDENCY-CVE`
  규칙은 통과할 수 없고 온라인 감사는 불완전하며 기본 `fail_on_partial` 정책은 종료 코드 3을
  반환합니다. 하루 안에 반복 실행하면 남은 패키지를 이어서 조회하며, 최근 하루 안의 OSV
  결과가 있는 패키지는 검사된 것으로 봅니다. 미확인 catalog alias와 OSV가 지원하지 않는
  생태계는 매 실행마다 온라인 오류로 보고되므로, 반복 실행해도 온라인 감사는 불완전하게
  남습니다.
- IPA 보고서에 `BINARY-IOS-CODE-INTEGRITY`가 추가됩니다. 해시가 일치해도 진위를 증명하지
  않습니다. 수정 후 다시 서명한 바이너리도 일치하기 때문입니다. 불일치는 발견 항목이 아닌
  경고를 추가하며, App Store 암호화·서명 없는 실행 파일은 `not-run`입니다.
- `intel sync`는 최근 Android 공지 범위만 갱신하므로 이전 달은 `intel backfill`을
  사용하세요. 1.2가 캐시한 공지는 컴포넌트 이름에서 vendor 범위를 도출하며, 칩셋·커널
  절이 아닌 항목은 플랫폼 패치 수준만 사용합니다. AAB feature 모듈의 설치 여부는 알 수
  없습니다.
- 호환 처리한 Swift·Objective-C 파일은 부분 분석으로 남고, 정규화한 전처리 조건부와
  겹치는 Objective-C 함수는 불확실로 분석에서 제외합니다. 수정하지 않은 1.2 스킬은
  `apsa skill install`로 업그레이드됩니다.

APSA 1.4는 개발자와 코딩 에이전트가 바로 쓸 수 있도록 배포 경로를 넓혔습니다. GitHub Action이
안정적인 fingerprint·보안 심각도·MASWE 태그·증거 상태를 담은 SARIF를 code scanning에 올리고,
모든 보고서에 [OWASP MASWE v1.0](https://mas.owasp.org/MASWE/) 커버리지 표가 붙어 APSA가 평가하지
않은 약점까지 명시합니다. MCP 서버는 MCP Registry와 Claude Code 플러그인으로 배포되며
[MCP 보안 모델](https://github.com/ictechgy/apsa/blob/main/docs/MCP_SECURITY.md)을 문서화했습니다.

**1.3에서 업그레이드할 때.**

- SARIF 내보내기는 결과가 있는 규칙마다 descriptor(도움말, `security-severity`, precision,
  MASVS/MASWE 태그)를 넣고, 발견 ID로 `partialFingerprints`를 만들며, not-run·partial 커버리지를 tool
  execution notification으로 보고합니다. 후보 발견은 `error`가 아닌 `warning`이며 규칙에 `candidate`
  태그가 붙습니다. `--sarif-root`로 위치를 저장소 기준 상대 경로로 만들고, URI는 퍼센트 인코딩하며,
  APK/AAB/IPA 내부 경로와 대상 밖 파일은 대상 위치의 logical location으로 표시합니다. 이 때문에 code
  scanning 경고가 한 번 새 키로 다시 생성될 수 있습니다.
- 새 소스 검사(외부 노출 컴포넌트, 백업, `targetSdk`, 개인정보 매니페스트, ATS 예외, 하드코딩된 비밀,
  안전하지 않은 난수, 모든 인증서 신뢰, 외부 저장소, Java 역직렬화, 추가 SQL sink, mutable
  `PendingIntent`)가 발견과 커버리지 항목을 추가합니다. `required_rules`나 심각도 게이트가 있는 정책은
  1.3에서 통과했어도 실패할 수 있으니, 게이트를 강화하기 전에 첫 1.4 보고서를 검토하세요.
- 규칙 메타데이터에 MASWE v1.0 ID가, 모델 context와 `capabilities`에 `maswe` 섹션이, Markdown
  보고서에 MASWE 커버리지 표가 추가됩니다. `reports ingest`로 만든 보고서에는 `external_inputs`와
  `origin: external` 발견이 추가되며 기존 필드의 의미는 그대로입니다.
- MCP 서버에 `verify_finding`, `specs_validate`, `reports_ingest_sarif`, `reports_checklist`,
  `reports_history`가 추가됩니다. `tool_manifest_sha256`은 이제 정규화한 APSA 소유 도구 정의의
  해시이므로 값이 바뀝니다. 고정해 둔 해시를 갱신하세요. 수정하지 않은 1.3 스킬은
  `apsa skill install`로 업그레이드됩니다.

APSA 1.5는 소스 스캔이 찾는 범위를 넓혔습니다. 새 검사는 MASTG 데모 미탐의 대부분에 해당하는 OWASP
MASWE 약점을 다룹니다. 깨진 cipher와 암묵적 ECB, 상수로 만든 키 재료와 IV, 짧은(512–1536비트) RSA·DSA·DH 키 크기,
CryptoKit `Insecure` 다이제스트, 키에 묶이지 않은 생체 인증 결과, 기기 비밀번호 대체 허용, 새 생체
등록 후에도 유지되는 키, TLS 1.2 미만, App Transport Security 밖의 iOS 연결, 네트워크 보안 설정의
사용자 CA·cleartext, 검증되지 않은 App Links, 인텐트 리다이렉션, 앱 내부용 암시적 Intent, 경로 조작,
secure coding 없는 keyed unarchiving, 꺼진 Safe Browsing, UIWebView, WKWebView 파일 접근입니다.
MASWE 약점으로 라벨을 붙인 공개 취약/수정 쌍 24개의 blind holdout에서 APSA 1.5.0은 채점한 평가 대상 21쌍
중 7쌍을 라벨 줄에서 찾았습니다(Wilson 95% 17–55%). 7쌍 중 2쌍은 1.5의 새 규칙이, 5쌍은 1.4에 있던 규칙이
찾았습니다. 수정 쪽 FP 상한은 21쌍 중 4쌍이며, 22번째 평가 대상 쌍은 스캔에 실패했습니다.
[blind 쌍 결과](https://github.com/ictechgy/apsa/blob/main/benchmarks/BLIND_PAIRS_RESULTS.ko.md)와
[분석 범위와 한계](https://github.com/ictechgy/apsa/blob/main/docs/NEXT_ANALYSIS.md)를 참고하세요.

**1.4에서 업그레이드할 때.**

- 새 규칙이 발견과 커버리지 항목을 추가합니다: `AST-CRYPTO-WEAK-CIPHER`, `IOS-CRYPTO-WEAK-CIPHER`,
  `AST-CRYPTO-HARDCODED-KEY`, `AST-CRYPTO-STATIC-IV`, `SOURCE-WEAK-KEY-SIZE`,
  `SOURCE-BIOMETRIC-EVENT-BOUND`, `SOURCE-BIOMETRIC-FALLBACK`, `SOURCE-BIOMETRIC-ENROLLMENT`,
  `SOURCE-WEAK-TLS-VERSION`, `IOS-ATS-BYPASS-API`, `ANDROID-NSC-USER-CA`, `ANDROID-DEEPLINK-AUTOVERIFY`,
  `AST-INTENT-REDIRECTION`, `AST-IMPLICIT-INTENT`, `IOS-WEBVIEW-FILE-ACCESS`, `WEBVIEW-SAFE-BROWSING-OFF`,
  `IOS-UIWEBVIEW`, `AST-PATH-TRAVERSAL`, `IOS-INSECURE-UNARCHIVE`. 기본 정책은 후보를 게이트에 쓰지
  않습니다. 새 configuration-confirmed 발견(`ANDROID-NSC-USER-CA`, 네트워크 보안 설정에서 나온
  `ANDROID-CLEARTEXT`)은 기본 `allowed_statuses`에 들어가지만 medium·low 기준은 기본으로 꺼져 있습니다. 후보나
  medium·low를 게이트에 쓰는 정책과 `only_new` 기준선에는 나타납니다.
- MASWE 표가 바뀝니다. MASWE-0003·0013·0020·0021·0022가 not-assessed에서 벗어나고(이 소스 검사는 APK·IPA를
  읽지 않으므로 그 입력에서는 not-run), `ANDROID-NSC-CONFIG`가 MASWE-0026·0027에 커버리지를 더합니다.
- 기존 규칙도 더 찾습니다. `AST-CRYPTO-ECB`는 `"AES"`만 쓴 transformation도 보고하며(제목이 "AES in ECB
  mode is selected"로 바뀌고 fingerprint는 그대로), `AST-CRYPTO-WEAK-HASH`는 CryptoKit `Insecure.MD5`·
  `Insecure.SHA1`을, `AST-SQL-CONCAT`은 `SQLiteQueryBuilder.query`, groupBy/having/orderBy/limit 인자,
  중첩 클래스로 선언한 외부 노출 provider를 봅니다. `SOURCE-INSECURE-RANDOM`은 Swift·Objective-C에서도
  실행되어 iOS 전용 트리의 커버리지가 not-applicable에서 checked로 바뀝니다.
- AST 엔진이 Kotlin `let`·`also`·`use`·`apply`·`run`·`with` 람다를 따라가므로, 모든 구조 규칙이 그 안의
  코드를 보고할 수 있습니다. `?.let` 람다나 `return@`이 있는 람다는 실행되지 않을 수도 있는 분기처럼
  병합하며, 항상 실행되는 람다 안의 재할당은 1.4의 발견을 없앨 수도 있습니다. 다른 람다와 Swift 클로저는
  여전히 분석하지 않습니다.
- `ANDROID-CLEARTEXT`는 참조된 네트워크 보안 설정에서도 나옵니다(configuration-confirmed이므로 code
  scanning이 심각도를 매깁니다). 그 설정을 해석했고 minSdk가 24 이상이며, 설정이
  `cleartextTrafficPermitted`를 명시했거나 targetSdk가 28 이상이면 매니페스트 `usesCleartextTraffic`
  후보는 빠집니다. 여러 소스셋이 정의한 설정에서 나온 발견은 후보입니다.
- 새 커버리지 상태로 감사가 불완전해질 수 있습니다. 참조된 설정을 해석할 수 없거나 스캔한 소스에 없거나
  빌드 placeholder이면 `ANDROID-NSC-USER-CA`·`ANDROID-NSC-CONFIG`가 partial이고, 일치 한도에 걸린 검사도
  partial입니다. 기본 `fail_on_partial`에서는 이런 스캔이 게이트에서 실패하고 기준선으로 내보낼 수
  없습니다. 컴파일된 AAB 설정은 not-run입니다.
- 텍스트 규칙은 패키지의 바이너리 XML을 checked로 세지 않으므로 APK에서 `WEBVIEW-SAFE-BROWSING-OFF`는
  not-run입니다. 규칙 리소스에 `case_sensitive`·`once_per_file`이 생길 수 있고, inventory에
  `deep_links[].browsable`·`network_security_parsed`가 추가됩니다. 수정하지 않은 1.4 스킬은
  `apsa skill install`로 업그레이드되며 MCP 도구 매니페스트 해시는 그대로입니다.

**1.5.0에서 업그레이드할 때.** 1.5.1은 큰 소스 트리를 거부하지 않고 부분 감사하며, Android 번역
파일에서 생기던 지연을 고칩니다.

- 텍스트 스테이징 한도(64 MiB, 파일 12,000개)를 넘는 소스 트리가 더 이상 입력 한도 오류(종료 코드 1)로
  끝나지 않습니다. 앱 코드·설정, 기타 출하 텍스트, Android 번역·한정자 `res/values-*` 파일, 테스트 순으로
  스테이징하고 빠진 것은 `inventory.input_snapshot.omitted`에 종류별로 셉니다. 감사는 불완전(종료 코드 3)이며
  기본 `fail_on_partial`에서는 게이트가 여전히 실패하고 부분 보고서는 기준선이 될 수 없습니다. 항목
  100,000개·깊이 64단계 한도도 거부 대신 읽기를 멈춥니다.
- 앱 코드·설정이나 기타 출하 텍스트가 빠지면(`app_scope_complete: false`) not-applicable coverage도
  partial이 되고 `DEPENDENCY-CVE`에 partial 항목이 추가되므로(`--sbom`으로 의존성을 준 경우 제외), `fail_on_partial = false`여도 필수 규칙은
  통과하지 않습니다.
- 이런 감사의 SARIF에는 경고 알림과 `run.properties.inputSnapshot`이 들어갑니다.
  `fail-on-incomplete: "false"`인 워크플로는 1.5.0에서 실패하던 경우에도 이제 경고와 함께 통과하고 부분 결과를
  올리며, code scanning은 생략된 파일의 결과를 보지 못합니다. 완전한 결과가 필요하면 `path`를 좁혀(모듈마다
  작업 하나, 각자의 `category`) 검사하세요. MCP 보고서 context의 `input`에 `input_snapshot`이 추가됩니다.
- 1.5.0에서는 프랑스어·이탈리아어 번역에 흔한 `\'`가 많은 `strings.xml` 때문에
  `WEBVIEW-SAFE-BROWSING-OFF`가 파서 시간 제한에 걸릴 만큼 느려질 수 있었습니다(694 KiB 파일에 약 150초).
  이제 XML 파일에서는 `<!-- -->` 주석만 지우므로 XML 텍스트의 `//`가 일치를 가리지 않습니다. 닫히지 않은
  문자열·주석에서도 주석 정리가 선형으로 끝나며, 뒤에 `*/`가 없는 `/*`는 일반 텍스트로 읽습니다.
- 수정하지 않은 1.5.0 스킬은 `apsa skill install`로 업그레이드되며 MCP 도구 매니페스트 해시는 그대로입니다.

## 검사 범위

| 영역 | 제공하는 검사 |
| --- | --- |
| 소스 코드 | Java·Kotlin·Swift AST 분석, 제한된 Objective-C `.m` 후보, WebView·딥링크 패턴, Manifest·Info.plist·저장소·의존성 검사(Gradle catalog 사용 근거·application lockfile 포함), exported 컴포넌트·백업·targetSdk, Apple required-reason API와 privacy manifest 대조, 알려진 형식의 자격증명(마스킹), 보안 값용 약한 난수, 변경 가능한 암시적 PendingIntent, 모든 인증서·호스트를 허용하는 TrustManager·HostnameVerifier, 평가 없이 수락한 iOS 서버 신뢰와 약화된 ATS 예외 도메인, 외부 저장소 쓰기, Java 역직렬화, (1.5) 깨진 cipher·상수 키와 IV·짧은 RSA 키, 생체 인증 결합과 대체 수단, TLS 버전, ATS 밖 iOS API, 네트워크 보안 설정, App Links, 인텐트 리다이렉션과 암시적 Intent, 경로 조작, keyed unarchiving, Safe Browsing, UIWebView와 WKWebView 파일 접근 |
| Android 빌드 | DEX 호출·상수 흐름, AAB base·feature 모듈 매니페스트와 모듈 DEX(항상 부분 감사), 리소스·네트워크 설정, exported 컴포넌트·provider, 서명 블록·v1 인증서 근거, ELF 하드닝 |
| iOS 빌드 | 내장 framework·확장 메타데이터를 포함한 Mach-O 헤더, CodeDirectory 페이지·entitlement 해시 무결성(서명 인증 아님), 제한적인 entitlement·설정 검사(내장 XML entitlement, ATS 예외, provisioning 지표), PIE·카나리·문자열 근거 |
| 공개 취약점 정보 | Apple·Android 공지(지정 기간의 Android 공지 소급 수집 포함), CVE, CISA KEV, OWASP 가이드, OSV 의존성 대조 |
| 보고서와 CI | SQLite 이력, 비교·재평가, JSON·Markdown·SARIF 내보내기, 필수 검사 범위, 만료일이 있는 예외 |
| 런타임 | 소유한 Android 테스트 앱과 iOS 시뮬레이터 앱의 준비된 시나리오. 실제 iOS 기기는 미지원 |
| 모델 연결 | stdio MCP 도구·리소스와 패키지 스킬. 특정 모델 제공자나 LLM API 키는 필수가 아님 |

발견 항목은 `candidate`, `configuration-confirmed`, `version-affected`, `runtime-confirmed` 근거를 구분합니다. `coverage`와 경고가 실제 실행한 범위를 표시합니다. 서명 블록의 존재가 서명 진위를 증명하지 않으며, 영향을 받는 의존성 버전이라고 해서 악용 가능성이 입증된 것은 아닙니다. 발견 항목이 없더라도 앱 전체가 안전하다고 판단할 수 없습니다.

OWASP 매핑은 관련 검사를 설명합니다. APSA는 MASVS 준수를 인증하거나 MASTG의 모든 테스트를 구현하지 않습니다. 공개 공지로 미공개 제로데이를 알아낼 수 없으며, 앱 파일만으로 실제 기기의 OS 패치 상태를 확정할 수 없습니다. 검증 범위와 한계는 [OWASP 대응 범위](https://github.com/ictechgy/apsa/blob/main/docs/OWASP_COVERAGE.md)와 [지원 표](https://github.com/ictechgy/apsa/blob/main/docs/SUPPORTED_MATRIX.md)를 참고하세요.

## 설치와 첫 실행

**macOS 또는 Linux**에서 **uv**를 설치합니다. APSA의 지원 대상은 **CPython 3.11과 3.12**이며, 모든 호스트·Python 조합을 테스트한 것은 아닙니다([지원 표](https://github.com/ictechgy/apsa/blob/main/docs/SUPPORTED_MATRIX.md) 참고). 예제는 Python 3.12를 선택하고 필요하면 uv가 내려받습니다. 최초 설치는 네트워크를 사용할 수 있으며, 이후 검사는 로컬 입력과 캐시를 사용할 수 있습니다.

[PyPI](https://pypi.org/project/apsa/)에서 배포 패키지를 설치합니다.

```sh
uv tool install --python 3.12 apsa==1.5.1
apsa --version
apsa doctor --json
apsa demo --out ./apsa-demo
```

패키지는 `apsa`와 호환 별칭 `quaygate`, `mobile-audit`를 제공합니다. 명령어를 찾을 수 없다면 `uv tool update-shell`을 실행하고 새 터미널을 여세요. [GitHub Releases](https://github.com/ictechgy/apsa/releases)에서는 wheel, 소스 패키지, 체크섬과 함께 고정 의존성 목록·라이선스 고지·빌드 manifest가 포함된 검증 번들을 제공합니다.

개발하거나 저장소의 고정 의존성으로 설치하려면 checkout을 사용합니다.

```sh
git clone https://github.com/ictechgy/apsa.git
cd apsa
uv sync --locked --python 3.12
uv run --locked apsa doctor --json
uv run --locked apsa demo --out ./apsa-demo
```

`doctor`는 파서, 선택적인 기기 도구, 오프라인 검사 준비 상태를 확인합니다. `demo`는 의도적으로 취약한 예제를 작성한 뒤 검사합니다. 새 출력 폴더를 지정하세요.

checkout의 명령어를 PATH에 등록하려면 다음을 실행합니다.

```sh
uv tool install --editable . --force --python 3.12 --constraints requirements-release.txt
apsa --version
```

`apsa`와 호환 별칭 `quaygate`, `mobile-audit`를 등록합니다. `--force`는 같은 명령어 이름으로 설치된 기존 도구를 교체합니다. editable 설치는 이 checkout에 의존하므로 폴더를 유지하세요. 명령어를 찾을 수 없다면 `uv tool update-shell`을 실행하고 새 터미널을 여세요. 아래 예제는 `apsa`가 PATH에 등록된 상태를 기준으로 합니다. 전역 설치 없이 실행하려면 checkout에서 각 명령 앞에 `uv run --locked`를 붙이세요.

```sh
apsa scan /path/to/owned/mobile-project
apsa scan /path/to/owned/app.apk
apsa scan /path/to/owned/app.ipa --sbom /path/to/build.cdx.json
apsa tui
```

실제 빌드에서 생성한 CycloneDX JSON SBOM을 제공하면 의존성 대조가 더 정확해집니다. `tui` 또는 인자 없는 `apsa`는 터미널 UI를 엽니다. 옵션은 `apsa COMMAND --help`로 확인할 수 있습니다.

## 공개 취약점 정보와 네트워크 사용

기본 `scan`은 로컬 파일과 캐시를 읽으며 소스 코드나 빌드를 업로드하지 않습니다. 공개 피드 수집과 OSV 조회는 네트워크를 사용합니다.

| 명령 | 네트워크 동작 |
| --- | --- |
| `apsa scan TARGET` | 로컬 입력과 캐시 사용 |
| `apsa intel sync` | 공개 취약점 정보 수집 |
| `apsa intel watch` | 공개 피드를 폴링하고 저장된 인벤토리를 재평가. 앱 파일을 다시 읽거나 OSV를 자동 조회하지 않음 |
| `apsa intel backfill --source android --since YYYY-MM` | 지정한 제한된 기간의 월별 Android 보안 공지를 수집 |
| `apsa scan TARGET --online` | 발견한 의존성 이름·버전을 OSV에 전송. 출하 구성에서 쓰는 Gradle catalog alias와 모든 모듈 lockfile의 release runtime 좌표를 포함하며 한 번에 최대 100개 패키지, 미검사 빌드 파일 선언 우선 |
| `apsa intel watch --online` | 저장된 의존성 이름·버전도 같은 한도로 OSV에 전송 |

```sh
apsa intel sync
apsa intel status
apsa intel watch --interval 900
apsa scan /path/to/owned/app --online
```

Watch는 기본 900초, 최소 60초 주기로 폴링하며 푸시 스트림은 아닙니다. `--cycles`로 횟수를 지정하지 않으면 중단할 때까지 실행합니다. 발견 항목, 검사 범위, 취약점 정보 상태가 달라지면 재평가가 새 스냅샷을 저장합니다. `intel status`로 피드 최신성, 실패, CVE 처리 대기열을 확인하세요. CVE 문서 수집과 처리 완료는 서로 다른 상태입니다. 기본 처리 대기열 정책은 미처리 항목을 허용하지 않으며 `intel_max_pending`으로 허용량을 명시할 수 있습니다.

```sh
apsa reports reassess latest
apsa reports compare audit_BEFORE audit_AFTER
apsa reports export latest --format sarif --out audit.sarif
apsa reports verify
```

재평가는 저장된 인벤토리에 현재 취약점 정보를 적용합니다. 파일 변경이나 새 정적 검사를 반영하려면 `scan`을 다시 실행하세요. 연결한 AI 클라이언트는 보고서 메타데이터를 모델 제공자에게 전송할 수 있습니다. APSA의 MCP context는 소스 발췌, 소스 원문, 스크린샷 바이트를 제외하지만, 클라이언트의 데이터 처리는 해당 클라이언트에 따라 달라집니다.

## CI와 백그라운드 작업

```sh
apsa policy init --out apsa.toml
apsa scan /path/to/owned/app --policy apsa.toml --out audit.json
apsa scan /path/to/owned/app --fail-on high --include-candidates
apsa scan /path/to/owned/app --background --json
apsa jobs status JOB_ID --json
```

심각도 기준 CI 판정은 기본적으로 `candidate`를 제외합니다. 포함하려면 `--include-candidates`나 정책의 `allowed_statuses`를 사용하세요. 필수 규칙은 `checked` 또는 `not-applicable` coverage만 인정하며, 부분 실행이나 필수 검사 누락은 통과시키지 않습니다. 예외에는 발견 ID, 이유, 만료일이 필요합니다. 백그라운드 작업의 `completed`는 작업이 끝났다는 뜻입니다. 감사가 완전한지 판단하려면 `audit_incomplete`와 보고서를 확인하세요.

읽을 수 없는 소스 폴더와 파일은 경고와 불완전한 coverage로 남습니다. 지원하는 파일을 하나도 읽을 수 없는 소스 트리는 명시적인 실행 오류가 됩니다. 텍스트 스테이징 한도(합계 64 MiB, 파일 12,000개)를 넘는 소스 트리는 거부하지 않고 부분 감사합니다. 앱 코드·설정(설정, 앱 코드, 헤더·`.build/`·`vendor/` 같은 vendored 코드 순), 기타 출하 텍스트(기본 리소스·JSON·YAML), Android 번역·한정자 `res/values-*` 파일, 테스트 순으로 스테이징하며, 빠진 파일 수와 바이트는 종류별(`code_and_config`, `other_text`, `localized_values`, `tests`)로 `inventory.input_snapshot.omitted`에 남습니다. 8 MiB 파일 한도를 넘거나 읽기·복사에 실패한 파일도 여기에 셉니다. 읽을 수 없는 디렉터리와, 트리 전체 기준 항목 100,000개(이름순으로 읽음)·깊이 64단계를 넘는 디렉터리는 경고로 보고합니다. 앱 코드·설정이나 기타 출하 텍스트가 빠지면 `app_scope_complete`가 false가 되고 not-applicable coverage도 partial이 됩니다. 완전한 감사가 필요하면 앱 모듈처럼 더 좁은 폴더를 검사하세요. 저장소 캡처 실패는 `not-run`으로 남으며 canary가 삭제됐다는 근거가 될 수 없습니다.

| 종료 코드 | 통합 CLI에서의 의미 |
| --- | --- |
| `0` | 명령 완료 또는 정책 통과 |
| `1` | 실행 오류 |
| `2` | 잘못된 인자 |
| `3` | 불완전한 감사·정책, 보고서 검증 실패, 취약점 정보 동기화 실패(부분 실패 포함) |
| `4` | 발견 항목이 설정한 CI 임계값 초과 |
| `130` | 중단 |

`--json`은 `ok`, `data` 또는 `error`, `exit_code`를 담은 envelope를 출력합니다. Watch는 주기마다 JSON envelope 하나를 출력합니다(NDJSON). `ok`는 코드 `0`과 `4`에서 `true`입니다. 코드 `4`는 평가 자체는 성공했지만 CI 임계값을 초과했다는 뜻입니다. CI는 `exit_code`와 정책 결과를 확인해야 합니다. 코드 `3`과 `4`에서도 보고서가 생성될 수 있습니다.

### GitHub code scanning

```yaml
permissions:
  contents: read
  security-events: write
  actions: read            # 비공개 저장소: 업로드가 워크플로 실행 정보를 읽을 수 있게 함
steps:
  - uses: actions/checkout@v7
    with:
      persist-credentials: false
  - uses: ictechgy/apsa@<commit-sha> # v1.5.1; 전체 커밋 SHA로 고정
    with:
      path: android            # 소스 폴더 또는 workspace 안의 APK/AAB/IPA
      fail-on-incomplete: "true"
```

Action은 같은 버전의 `apsa`를 릴리스의 해시 고정 의존성과 함께 PyPI에서 설치하고
`scan --format sarif --sarif-root`를 실행한 뒤 작업 요약을 쓰고 SARIF를 code scanning에 업로드하며,
마지막에 결과를 적용합니다. 정책 실패나 `fail-on` 임계값 초과는 감사가 불완전하더라도 작업을
실패시킵니다(종료 코드 `3`이 임계값 실패를 가릴 수 있어 Action은 종료 코드만이 아니라 보고서를
읽습니다). 정책을 쓰면 필수 규칙·필수 취약점 정보·만료된 예외·기준선 검사 등 충족하지 못한 정책
조건은 모두 작업을 실패시키고, 부분 감사만 `fail-on-incomplete`에 맡깁니다. 이 값이 `"false"`가 아니면
종료 코드 `3`도 실패합니다. 팀 게이트는
`policy`(필요 시 `baseline-file`, `baseline-sha256`), 단순 임계값은 후보를 제외하는 `fail-on`을 쓰세요.

기본값의 Action은 오프라인이라 CVE·의존성 공지 대조를 하지 않습니다. 의존성 발견에는 `intel-sync`(공개
공지를 먼저 수집, 부분 동기화는 경고)와 `online`(의존성 이름·버전을 OSV에 전송)이 필요합니다. 비공개
저장소의 SARIF 업로드에는 GitHub Code Security가 필요하며, `upload-sarif: "false"`면 파일만 남깁니다.
fork의 pull request와 Dependabot이 실행한 모든 워크플로는 읽기 전용 토큰을 받으므로 Action이 업로드를
건너뛰고 파일과 요약만 남깁니다.

각 경고의 fingerprint는 APSA 발견 ID, 즉 규칙과 증거 위치(파일, 줄, 함수 또는 아카이브 내부 경로)입니다.
표시된 줄을 고치거나 파일을 옮기면 경고 하나가 닫히고 새 경고가 열릴 수 있습니다. 후보 발견은
`warning` 수준과 `candidate` 태그로 올라가며, 결과가 모두 후보인 규칙에는 `security-severity`를 넣지 않아
code scanning 기본 검사(High·Critical 경고에서 실패)를 일으키지 않습니다. 확인된 결과가 있는 규칙은 그
결과로 `security-severity`를 정하며, 같은 규칙의 후보 경고도 그 등급을 공유합니다. code scanning은 `category`(기본 `apsa`)별로 경고를
추적하므로, 이전에 다른 category로 APSA SARIF를 올렸다면 그 값을 유지하세요. 새 category는 새 경고를
만들고, 이전 category의 경고는 해당 분석을 삭제할 때까지 열려 있습니다. 요금제에 따라 GitHub가 서드파티
경고에 [Copilot Autofix](https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/responsible-use-autofix-code-scanning)
제안을 붙일 수 있지만 APSA 경고로는 시험하지 않았으며, APSA 증거 상태는 각 경고의 properties에 남습니다.

Action 없이:

```sh
apsa scan android --format sarif --out apsa.sarif --sarif-root android
apsa reports export latest --format maswe --out maswe.json
apsa reports export latest --format cyclonedx --out apsa.cdx.json
```

`reports ingest REPORT --sarif FILE --tool NAME`(MCP `reports_ingest_sarif`)은 Android Lint·CodeQL·
Semgrep 같은 다른 도구의 SARIF 2.1.0 결과를 새 보고서로 가져옵니다. 가져온 결과는 `origin: external`
후보로 남고 APSA 검사 범위를 늘리지 않으며, 같은 위치의 관련 약점 APSA 발견과 서로 연결됩니다. 문구는
정리 후 신뢰하지 않는 데이터로 다룹니다.

`--format checklist --checklist masvs-v2`(또는 기관 점검 항목을 MASWE·APSA 규칙에 연결한 TOML)는 항목별
관련 검사 상태와 발견을 정리하며 "통과"를 판정하지 않습니다. `reports history TARGET`은 발견 항목별
최초·최종 관찰과 해소 시점을 점검·조치 이력으로 보여 줍니다. [국내 점검 기준과 함께 쓰기](https://github.com/ictechgy/apsa/blob/main/docs/KOREA.md)를
참고하세요.

`--format cyclonedx`는 APSA가 찾은 의존성의 CycloneDX 1.6 SBOM(package URL, 버전 근거 포함)을
쓰고, 의존성 CVE 대조 결과를 VEX 항목으로 넣습니다. 각 항목에는 증거 상태, CISA KEV 여부, 해당
대상에서 APSA가 처음 관찰한 시각이 있어 EU 사이버복원력법(CRA) 같은 취약점 처리 기한 관리에 쓸 수
있습니다. 분석 상태는 모두 `in_triage`이며 APSA는 `not_affected`를 자동으로 쓰지 않으니, 그 판단은
근거와 함께 직접 기록하세요. 이 SBOM은 완전한 빌드 목록이 아니며 어떤 규정 준수도 보장하지 않습니다.

정책·백업·제한·문제 해결은 [CI 예제](https://github.com/ictechgy/apsa/blob/main/docs/ci-example.yml)와 [운영 가이드](https://github.com/ictechgy/apsa/blob/main/docs/OPERATIONS.md)를 참고하세요.

## MCP와 스킬

```sh
apsa integrations --root /absolute/path/to/owned-apps
apsa mcp --root /absolute/path/to/owned-apps
apsa skill install
apsa context --report latest --section findings --limit 20 --json
```

`integrations`가 설치된 실행 파일 경로를 포함한 설정을 생성합니다. `apsa` 실행 파일을 찾지 못하면 `python -m apsa`를 사용하는 설정을 만듭니다. 아래는 형식을 보여주는 예제입니다. 두 절대 경로를 실제 경로로 바꾸세요.

```json
{
  "mcpServers": {
    "apsa": {
      "command": "/absolute/path/to/apsa",
      "args": ["mcp", "--root", "/absolute/path/to/owned-apps"]
    }
  }
}
```

### 에이전트에 설치

| 클라이언트 | 설치 |
| --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/apsa` 후 `/plugin install apsa@apsa`. 플러그인은 `uvx --python 3.12 apsa@VERSION mcp --root <현재 프로젝트>`를 실행하고 스킬을 추가합니다. |
| 모든 MCP 클라이언트 | `apsa integrations` 설정 또는 MCP Registry 항목 `io.github.ictechgy/apsa`(PyPI 패키지, `uvx`, 필수 `--root`). |
| Codex 등 스킬 런타임 | `apsa skill install`과 `integrations` 설정. |

릴리스 전에 Claude Code 2.1.295(체크아웃의 플러그인을 `--plugin-dir`로 로드, root
`${CLAUDE_PROJECT_DIR}`)와 Codex CLI 0.162.0에서 이 버전의 로컬 빌드로, 새로 만든 합성 프로젝트에 대해
`capabilities`·`audit_scan` 호출을 각각 확인했습니다. 마켓플레이스와 MCP Registry 설치는 패키지 게시 후
확인합니다. 다른 클라이언트는 아직 검증하지 않았습니다.

MCP는 stdio를 사용하며 명시적인 `--root`가 필요합니다. 여러 root는 옵션을 반복해서 지정합니다. `integrations`에 root를 주지 않으면 현재 폴더를 사용합니다. Root는 검사 대상과 해당 보고서·작업 접근을 제한합니다. `--allow-any-root`는 이 제한을 명시적으로 해제합니다. APSA는 모델 클라이언트 설정을 자동 변경하지 않으며, 클라이언트 인증은 클라이언트가 관리합니다.

| 목적 | MCP 도구 |
| --- | --- |
| 감사 | `capabilities`, `audit_scan`, `audit_start`, `audit_reassess`, `verify_finding`, `specs_validate` |
| 작업 | `jobs_list`, `jobs_status`, `jobs_cancel` |
| 보고서 | `reports_list`, `reports_get`, `reports_compare`, `reports_export_baseline`, `reports_ingest_sarif`, `reports_checklist`, `reports_history` |
| 취약점 정보 | `intelligence_sync`, `intelligence_search`, `intelligence_get`, `dependency_check` |
| 정책 | `policy_evaluate` |
| 런타임 계획 | `runtime_plan`, `runtime_devices` |

`verify_finding`(CLI `apsa verify`)은 다른 도구나 AI 리뷰어가 주장한 발견을 APSA 증거와 대조하며 반박하지 않습니다. 프로젝트 taint 명세는 딥링크 파서나 인앱 브라우저 래퍼 같은 프로젝트 고유 source·sink를 지정해 APSA가 결정적으로 추적하게 합니다. [프로젝트 명세](https://github.com/ictechgy/apsa/blob/main/docs/PROJECT_SPECS.md)를 참고하세요.

`capabilities`는 APSA가 정의한 도구 이름·설명·annotation·파라미터 형태를 정규화한 해시
`tool_manifest_sha256`을 알려 주며, 한 프로세스 안에서 도구 목록은 바뀌지 않습니다. 서버가 스스로
보고한 값을 믿기보다 `tools/list`로 계산한 해시를 공개 값과 비교하세요. 읽기 전용 도구는 read-only·idempotent,
네트워크 도구는 open-world로 표시합니다. 앱 내용과 공지 문구는 신뢰하지 않는 데이터로 다루며 모델
context에는 원문 발췌가 없습니다. [MCP 보안 모델](https://github.com/ictechgy/apsa/blob/main/docs/MCP_SECURITY.md)을 참고하세요.

제공하는 리소스에는 `apsa://rules`와 `apsa://reports/{report_id}`가 있으며, 기존 `quaygate://`·`mobile-audit://` scheme도 호환됩니다.

보고서 context는 기본 20개 항목·64 KiB로 제한됩니다. `latest`를 한 번 조회한 뒤 반환된 보고서 ID와 `page.next_cursor`로 이어 읽고, section과 필터는 유지하세요. `partial_response`는 응답 페이지 상태, `audit_incomplete`는 감사 실행 상태입니다. 너무 큰 항목은 생략 사실을 표시하며 로컬 내보내기로 확인할 수 있습니다. 휴대형 기준선에는 명시적인 승인 정보와 검토된 CI 설정에 고정한 SHA-256이 필요합니다. [워크플로 예제](docs/MODEL_WORKFLOWS.md)를 참고하세요.

기본 서버는 런타임 계획 기능을 제공합니다. `runtime_execute`와 `runtime_start`는 서버 시작 시 `--allow-runtime`을 지정해야 등록됩니다. 두 도구는 기본적으로 시나리오를 미리보기하며 `execute=true`일 때 실행합니다. `runtime_start`는 취소 가능한 백그라운드 기기 작업을 시작합니다. 런타임 검사에는 승인받고 준비한 테스트 앱이 필요하며, 기본 감사는 기기를 부팅하거나 앱을 설치하지 않습니다. 시나리오 실행 전 [운영 가이드](https://github.com/ictechgy/apsa/blob/main/docs/OPERATIONS.md)를 확인하세요.

`skill install`은 패키지의 [APSA 스킬](https://github.com/ictechgy/apsa/blob/main/.agents/skills/apsa/SKILL.md)을 `~/.codex/skills/apsa`에 복사합니다. 다른 모델 런타임의 스킬 폴더에 직접 설치할 수도 있습니다.

```sh
apsa skill install --name apsa --dest /path/to/runtime/skills/apsa
```

이전 기본 이름으로 설치한 스킬은 `--name quaygate` 또는 `--name mobile-audit`로 갱신할 수 있으며, 사용자 수정본은 `--force`가 없으면 보존합니다. `integrations`는 스킬 상태를 표시합니다. MCP를 지원하지 않는 클라이언트에는 `context`로 소스 발췌·원문·스크린샷 바이트를 제외한 보고서 근거를 전달할 수 있습니다.

## 기존 사용자와 데이터 호환

`quaygate`와 `mobile-audit`는 같은 통합 CLI를 호출합니다. `python -m apsa`, `python -m quaygate`, `python -m mobile_audit`도 계속 사용할 수 있습니다. 기존 보고서와 `QG-*` 규칙 ID의 식별자를 유지합니다.

기본 데이터 저장 위치는 `~/.local/share/mobile-audit`입니다. 경로 우선순위는 `--home` → `APSA_HOME` → `QUAYGATE_HOME` → `MOBILE_AUDIT_HOME` → 기본 경로입니다. 리네이밍으로 DB를 복제하거나 이력을 옮기지 않습니다. 기존 MCP 설정에는 승인된 `--root`가 필요합니다.

기존 `apk`, `ipa`, `device` 하위 명령은 빠른 린트 출력과 종료 코드 `0/1/2`를 유지합니다. 통합 감사 이력을 저장하거나 취약점 정보를 대조하지 않으므로 전체 흐름에는 `scan`을 사용하세요. 심각도가 없는 구버전 OSV 캐시는 `scan --online` 또는 `intel watch --online`으로 다시 조회해야 합니다. 재평가만으로 누락된 점수를 복구할 수 없습니다.

## 개발·검증·라이선스

```sh
uv sync --locked --extra dev --python 3.12
make test benchmark
make export-release
make release RELEASE_OUT=dist/apsa-local-release
```

새 폴더나 비어 있는 릴리스 폴더를 지정하세요. 릴리스 검증은 uv **0.12.1**을 요구하며 wheel·sdist를 두 번 빌드해 해시를 비교합니다. checkout 밖의 새 환경에서 오프라인 소스·APK 검사, MCP, 스킬 설치를 확인합니다. 해시, SBOM, 의존성 고지, 릴리스 manifest를 작성하며 게시하지 않습니다. 최초 의존성 준비는 네트워크를 사용할 수 있습니다. 같은 호스트의 반복 빌드 검증은 다른 플랫폼 간 바이트 일치를 의미하지 않습니다.

릴리스 태그의 배포는 GitHub Actions에서 지원 대상 CI 조합이 모두 통과한 뒤 검증된 패키지를 PyPI에 업로드합니다. 워크플로와 다운로드 구성은 [배포 안내](https://github.com/ictechgy/apsa/blob/main/docs/PUBLISHING.md)를 참고하세요.

제품 검증 기록은 [RELEASE_READINESS.md](https://github.com/ictechgy/apsa/blob/main/RELEASE_READINESS.md)에 있습니다. [선별한 벤치마크](https://github.com/ictechgy/apsa/blob/main/benchmarks/README.md)(영문)는 회귀 검사 사례 모음이며 운영 앱 탐지율을 나타내지 않습니다. 구조와 보안 경계는 [통합 경계](https://github.com/ictechgy/apsa/blob/main/docs/INTEGRATION.md)와 [위협 모델](https://github.com/ictechgy/apsa/blob/main/docs/THREAT_MODEL.md)에서 확인할 수 있습니다. 과거 리뷰는 당시 스냅샷에만 적용됩니다.

새로 생성한 합성 소스 프로젝트와 APK를 사용하는 [APSA/MobSF 비교](benchmarks/COMPETITIVE.md)(영문)와
[측정 결과](benchmarks/COMPETITIVE_RESULTS.ko.md)를 제공합니다. APSA 1.2.0 배포 전의
개발 후보를 측정한 결과이며 배포 패키지의 측정이나 운영 앱의 정확도를 나타내지 않습니다.
APSA 1.3.0 릴리스 런타임에서 새로 생성한 입력으로 다시 실행해 후보 수치를 재현했습니다
([RELEASE_READINESS.md](https://github.com/ictechgy/apsa/blob/main/RELEASE_READINESS.md)).

별도의 [공개 소스·CVE 평가](benchmarks/REAL_WORLD.ko.md)와
[최초 결과](benchmarks/REAL_WORLD_RESULTS.ko.md)는 커밋을 고정한 앱 소스 6개,
선택한 의존성·CVE, OS 공지 사례를 검증합니다. 의존성 추출 누락·분석 실패·
불완전한 커버리지를 유지하며 앱 전체의 보안이나 일반적인 운영 정확도를
측정하지 않습니다.

이후 [보강 재평가](benchmarks/HARDENING_RESULTS.ko.md)에서 앱 소스 6개 모두 검사를
완료하고 측정한 연동 누락 네 가지를 수정했습니다. 관찰한 정답을 재사용한
개발 검증이며, 남아 있는 불완전한 커버리지를 함께 기록했습니다.

[커버리지 확장 평가](benchmarks/COVERAGE_RESULTS.ko.md)는 제한된 Swift/Kotlin
구문 호환, 인식한 함수 수, Apple 근거에 따른 iOS/iPadOS 분기 판정을 기록합니다.
호환 처리한 소스는 부분 분석으로 남으며, 선택한 사례로 일반적인 CVE 정확도를
입증하지 않습니다.

[추가 분석·독립 정답 평가](benchmarks/NEXT_RESULTS.ko.md)는 AAB·IPA 메타데이터,
Objective-C, 파서 격리와 독립 라벨의 새 공개 소스 2개를 다룹니다.
선택한 CVE 경계 일치, catalog 사용 미확인과 남은 구문 누락을 별도로 기록합니다.

[의존성 근거 평가](benchmarks/DEPENDENCY_RESULTS.ko.md)는 APSA의 Gradle catalog 사용 근거와
lockfile 좌표를 공개 앱 holdout 3개에서 Gradle 자체 해석과 비교하며, 최초 블라인드 결과와
정답을 본 뒤의 재실행을 구분합니다. [독립 취약·수정 소스 쌍](benchmarks/FPFN_RESULTS.ko.md)은
공개 프로젝트의 취약·수정 커밋을 스캔 전에 고정한 정답으로 채점합니다.
[blind MASWE 라벨 쌍](benchmarks/BLIND_PAIRS_RESULTS.ko.md)은 약점으로 라벨을 붙인 새 holdout에서 1.5를
측정하고, [OWASP MASTG 데모](benchmarks/MASTG_RESULTS.ko.md)는 개발용 벤치마크입니다. 모두 좁은 표본이며
일반적인 정확도 추정이 아닙니다.

소스는 [GitHub](https://github.com/ictechgy/apsa)에 공개되어 있습니다. [LICENSE](https://github.com/ictechgy/apsa/blob/main/LICENSE)는 원래 Quaygate의 MIT 고지를 보존합니다. 이번 공개는 통합 제품에 추가 라이선스를 선언하지 않습니다.

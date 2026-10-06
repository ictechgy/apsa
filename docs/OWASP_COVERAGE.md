# OWASP 모바일 검사 범위

APSA (앱사)는 [OWASP MASVS](https://mas.owasp.org/MASVS/)의 관련 영역에 개별 증거를 연결합니다. 하나의 규칙이 control이나 [MASTG](https://mas.owasp.org/MASTG/) 테스트의 모든 절차를 구현한다는 뜻은 아닙니다. 실행 보고서의 `coverage`와 `mapping_scope`가 실제 수행 범위를 나타내며, `apsa rules --json`과 MCP `apsa://rules`에서 구현한 규칙을 조회할 수 있습니다.

| MASVS 영역 | 실행하는 검사 | 결과의 의미·남은 범위 |
| --- | --- | --- |
| PLATFORM | Java/Kotlin/Swift 함수 내 외부 URL→WebView 흐름, 파싱된 host/scheme guard, 문자열 allowlist, bridge·file-origin API, Manifest와 URL scheme, target delivery marker | AST·DEX는 후보. 함수 간 흐름·redirect·반사·동적 로딩·모든 deep-link 인증 경로를 증명하지 않음 |
| NETWORK | SSL handler proceed, 명시적 Android cleartext 설정, iOS ATS 예외 | 후보 또는 설정 증거. 실제 TLS handshake·모든 도메인 trust·pinning 테스트 없음 |
| STORAGE | 민감정보 로그·ordinary preferences·Keychain 접근 정책 패턴, DEX 호출과 상수, 로그아웃/계정 전환 후 canary persistence | 정적 후보 또는 지정 capture에서 런타임 관찰. Keychain/clipboard 전체·백업 정책·모든 민감 데이터 자동 열거 없음 |
| AUTH | 로그아웃 전후 상태 marker와 보호된 deep-link/UI canary assertion | 테스트한 앱 상태·화면 노출의 증거. 서버 토큰 invalidation·MFA·세션 전체 검사 없음 |
| RESILIENCE | Android debuggable·WebView debugging, Mach-O PIE·내장 XML debug entitlement | 설정 또는 정적 후보. 서명 진위·DER entitlement 의미·모든 anti-tamper 검사 없음 |
| CODE 및 공급망 | 실제 빌드 SBOM/선언된 의존성과 OSV, Apple/Android/CVE/KEV의 버전·환경 대조 | 버전 영향과 출처를 보존. 선언된 의존성이 실제 포함됐는지·도달 가능한지·exploit 재현은 별도 |

Java/Kotlin/Swift의 구조 분석은 설치 시 포함한 Tree-sitter grammar를 사용합니다. Objective-C·Dart·JavaScript 등은 일부 명시한 패턴 검사만 제공하며 구조 분석은 지원하지 않는다고 표시합니다. APK는 실제 DEX instruction을 읽고, IPA는 Mach-O 구조와 일부 설정을 읽습니다. 문자열에 API 이름만 존재한다는 이유로 DEX 호출을 검출하지 않습니다.

스캔 전 환경 정보가 없거나 런타임을 실행하지 않았으면 해당 범위는 `not-run`입니다. 캡처 실패·검사 한도는 `partial`/`not-run`, baseline 또는 전환 증거 부족은 `inconclusive`입니다. CI 정책의 `required_rules`와 인텔 최신성 조건으로 팀이 필요한 수행 범위를 지정할 수 있습니다.

런타임 잔존 정보 coverage는 `purpose=residual`인 canary assertion이 실제로 완료돼야 `checked`입니다. purpose를 생략한 기존 assertion은 residual로 해석합니다. 발견된 잔존 정보 때문에 assertion이 `failed`여도 검사는 수행된 것이며, finding과 CI 심각도 정책으로 판정합니다. 전달·전환·인증만 검사한 시나리오는 잔존 정보 검사를 대신하지 않습니다.

검사 정확도는 [31개 수작업 corpus](../benchmarks/README.md)와 안전/위험 fixture, 별도의 [실제 런타임 8개 조합](../tests/fixtures/runtime/README.md)으로 평가합니다. 이 점수를 운영 앱 전체 탐지율이나 MASVS 인증으로 일반화하지 않습니다. 라이브 OWASP 카탈로그 갱신은 가이드 데이터를 업데이트하며, 새 테스트의 검사 코드를 자동 생성하거나 통과 처리하지 않습니다.

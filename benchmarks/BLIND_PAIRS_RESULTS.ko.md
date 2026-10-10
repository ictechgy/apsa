# MASWE 라벨 취약/수정 쌍 blind 측정 (APSA 1.5.0)

영어 원본은 [BLIND_PAIRS_RESULTS.md](BLIND_PAIRS_RESULTS.md)이며, 이 문서는 그 번역입니다.

Android·iOS 앱과 SDK의 공개 취약/수정 커밋 쌍 24개에서 APSA 1.5.0을 처음으로, blind로 측정한
결과입니다. 쌍은 APSA 규칙이 아니라 [OWASP MASWE v1.0](https://mas.owasp.org/MASWE/) 약점으로
라벨을 붙였습니다. 아래 결과는 실행된 그대로 기록하며, 이 정답으로 이후에 돌리는 실행은 모두 개발
재실행입니다.

## 방법

- **정답 선정.** 독립 에이전트가 공개 advisory와 보안 수정 커밋에서 쌍을 고르고 라벨을 붙였으며,
  모든 SHA·경로·줄 범위를 GitHub API로 확인한 뒤 [`fpfn_truth_holdout2.json`](fpfn_truth_holdout2.json)
  (sha256 `c42c9cd345265e8621f5f8d46dce2bc8c0b993ba05f782c97756bc8c8eaae5df`)으로 고정했습니다.
  이 에이전트는 APSA를 실행하거나 규칙을 읽지 않았고, 집계 수치와 파일 해시만 전달했습니다.
- **blind 조건.** 큐레이터를 조율한 에이전트와 1.5 규칙을 작성한 에이전트는 같습니다. 이 에이전트는
  첫 실행 전까지 정답 파일, 큐레이터의 작업 파일, 쌍별 내용을 열지 않았고, 코드·아키텍처 리뷰어에게도
  같은 제한을 두었습니다. 따라서 blind 조건은 구조적 분리가 아니라 이 진술에 근거합니다. 정답 파일은
  커밋 이후 작성자의 체크아웃 안에 있었습니다. 다음 holdout은 정답 파일을 작성자의 체크아웃 밖에 두고
  실행 전까지 해시만 커밋해야 합니다.
- **공개한 계획과의 차이.** 1.4 로드맵에는 1.5 규칙을 쓰기 전에 holdout을 고정한다고 적었습니다.
  실제로는 규칙 작성과 동시에 정답을 만들었습니다(규칙 `9562717` 13:04 KST, 정답 선정 완료 13:29,
  `be1911b`로 13:33 커밋). 고정 이후 리뷰에 따른 커밋이 6개(`35d2d88`~`1fac679`) 있었고, 이 중 어느
  것도 정답을 보지 않았습니다.
- **측정한 코드.** `1fac679`(`src` 트리 `268ae9699b9ac0bdf9068bc091d36f986487ae1c`, 패키지 `1.5.0`,
  모든 쌍의 양쪽에서 규칙 버전 `2026.10.10.apsa.150`)를, 런타임 코드를 바꾸지 않고 워크플로만 추가한
  `47ce760`을 통해 실행했습니다. [실행 38028093532](https://github.com/ictechgy/apsa/actions/runs/38028093532)는
  깨끗한 CI 체크아웃(`worktree_dirty: false`)이었고, 평가기 sha256은
  `af908a0891ad5c283625cc578e0a45a3d6e4167d397c75aa35ef367ccd3b782b`, 보정은 없습니다. 원본 결과는
  [`results/2026-10-10-blind-holdout2-first.json`](results/2026-10-10-blind-holdout2-first.json)입니다.
- **채점(실행 전 `fpfn_eval.py`에 선언).** 쌍의 약점에 매핑된 APSA 발견이 라벨 파일에 증거를 가지면
  그 쪽을 탐지로 봅니다. 주 지표는 라벨 줄 범위(±3) 안의 줄 단위 TP입니다. 보조 지표는 판별 TP로,
  범위 안에서 맞힌 규칙이 수정 쪽 라벨 파일에서는 발화하지 않은 경우입니다. 수정 쪽에는 줄 범위가 없어
  FP는 파일 단위이며 상한입니다. APSA 소스 검사가 쌍의 약점과 관련 있으면 평가 대상(in scope)으로 보는데,
  이 정의는 넓어서(MASWE-0050 쌍은 모두 포함) 평가 대상 recall은 규칙군이 아니라 약점 수준입니다.

## 결과

24쌍 중 23쌍을 채점했고 1쌍은 스캔에 실패했습니다. 채점한 쌍 중 21쌍이 평가 대상입니다. 구간은 Wilson
95%입니다.

| 지표 (평가 대상 쌍) | 수치 |
| --- | --- |
| 줄 단위 TP (주 지표) | **21쌍 중 7쌍** (33%, 17–55%); 실패한 스캔을 놓친 것으로 치면 22쌍 중 7쌍 |
| 판별 TP | 21쌍 중 5쌍 (24%, 11–45%) |
| 파일 단위 TP / FN | 9 / 12 |
| 수정 쪽 FP / TN (상한) | 4 / 17 (FP 19%, 8–40%) |

전체 쌍 기준(평가 대상 밖 쌍은 FN): TP 9, FN 14, FP 4, TN 19, 줄 단위 TP 7, 판별 TP 5, 오류 1,
미채점 0.

규칙 ID로 라벨을 붙인 [1.3 소스 쌍](FPFN_RESULTS.ko.md)과는 라벨 방식이 달라 비교할 수 없습니다.

줄 단위로 맞힌 7쌍 중 2쌍은 1.5에서 추가한 규칙(`SOURCE-BIOMETRIC-EVENT-BOUND`,
`SOURCE-BIOMETRIC-ENROLLMENT`)이 찾았고, 나머지 5쌍은 1.4에 이미 있던 규칙(PendingIntent 가변성,
모든 인증서 신뢰, WebView 파일 출처 접근, Java 역직렬화, Swift 서버 신뢰)이 찾았습니다. 1.5 규칙이
수정 쪽 FP를 낸 경우는 없습니다.

## 쌍별 결과

| 쌍 | 플랫폼 | MASWE | 평가 대상 | 취약 쪽 | 줄 단위 | 판별 | 수정 쪽 | 취약 쪽 규칙 | 수정 쪽 규칙 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [element-android-mainactivity-intent-redirection](https://github.com/element-hq/element-android/security/advisories/GHSA-j6pr-fpc8-q9vm) | android | 0032 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [nextcloud-android-implicit-mutable-pendingintent](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5cj3-v98r-2wmq) | android | 0032 | 예 | TP | 예 | 예 | TN | `AST-PENDINGINTENT-MUTABLE` | – |
| [nextcloud-talk-android-share-filename-path-traversal](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-36f7-93f3-mcfj) | android | 0050 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [nextcloud-talk-android-unprotected-pip-receiver](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-564v-3rfc-352m) | android | 0032, 0018 | 예 | TP | 아니요 | 아니요 | FP | `AST-PENDINGINTENT-MUTABLE` | `AST-PENDINGINTENT-MUTABLE` |
| [capgo-native-biometric-event-only-auth](https://github.com/advisories/GHSA-vx5f-vmr6-32wf) | android | 0020 | 예 | TP | 예 | 예 | TN | `SOURCE-BIOMETRIC-EVENT-BOUND` | – |
| [osmand-open-gpx-deeplink-path-traversal](https://securitylab.github.com/advisories/GHSL-2026-106_OsmAnd/) | android | 0029, 0050 | 예 | 오류 | – | – | 오류 | 스캔 거부(입력 스테이징 한도) | – |
| [mifos-mobile-trust-all-hostname-verifier](https://github.com/openMF/mifos-mobile/security/advisories/GHSA-9657-33wf-rmvx) | android | 0027 | 예 | TP | 예 | 예 | TN | `SOURCE-HOSTNAME-VERIFIER-ALL`, `SOURCE-TRUST-ALL-CERTS` | – |
| [salesforce-android-login-webview-file-url-access](https://github.com/forcedotcom/SalesforceMobileSDK-Android/pull/2546) | android | 0034 | 예 | TP | 예 | 예 | TN | `WEBVIEW-FILE-ACCESS` | – |
| [salesforce-android-login-passcode-no-flag-secure](https://github.com/forcedotcom/SalesforceMobileSDK-Android/pull/1100) | android | 0038 | 아니요 | FN | 아니요 | 아니요 | TN | – | – |
| [freeotp-android-scan-activity-no-flag-secure](https://github.com/freeotp/freeotp-android/pull/125) | android | 0038 | 아니요 | FN | 아니요 | 아니요 | TN | – | – |
| [newpipe-backup-import-objectinputstream](https://github.com/TeamNewPipe/NewPipe/security/advisories/GHSA-wxrm-jhpf-vp6v) | android | 0050 | 예 | TP | 예 | 아니요 | FP | `SOURCE-JAVA-DESERIALIZATION` | `SOURCE-JAVA-DESERIALIZATION` |
| [airmapview-webview-default-file-access](https://github.com/airbnb/AirMapView/pull/72) | android | 0034 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [stytch-android-pkce-time-seeded-random](https://github.com/stytchauth/stytch-android/pull/145) | android | 0012 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [keepassdroid-password-generator-java-util-random](https://github.com/bpellin/keepassdroid/pull/62) | android | 0012 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [home-assistant-ios-url-actions-without-confirmation](https://github.com/home-assistant/core/security/advisories/GHSA-h2jp-7grc-9xpp) | ios | 0029 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [home-assistant-ios-script-bridge-all-frames](https://github.com/home-assistant/core/security/advisories/GHSA-7jp2-p2fw-mgvf) | ios | 0033 | 예 | TP | 아니요 | 아니요 | FP | `WEBVIEW-JS-BRIDGE` | `WEBVIEW-JS-BRIDGE` |
| [cryptomator-ios-keychain-biometry-any](https://github.com/cryptomator/ios/security/advisories/GHSA-fmh3-xfw7-38cj) | ios | 0022 | 예 | TP | 예 | 예 | TN | `SOURCE-BIOMETRIC-ENROLLMENT` | – |
| [cryptomator-ios-cache-in-icloud-backup](https://github.com/cryptomator/ios/security/advisories/GHSA-385v-vfgq-jxc9) | ios | 0006 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [salesforce-ios-push-secret-rsa-pkcs1-fallback](https://github.com/forcedotcom/SalesforceMobileSDK-iOS/pull/4127) | ios | 0007 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [zipfoundation-uncontained-symlink-extraction](https://github.com/advisories/GHSA-c2cc-3569-6jh2) | ios | 0050 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [afnetworking-default-policy-no-domain-validation](https://nvd.nist.gov/vuln/detail/CVE-2015-3996) | ios | 0027 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [vlc-ios-openurl-before-passcode](https://nvd.nist.gov/vuln/detail/CVE-2018-19937) | ios | 0020 | 예 | FN | 아니요 | 아니요 | TN | – | – |
| [telnyx-ios-sdk-self-signed-certs-accepted](https://github.com/team-telnyx/telnyx-webrtc-ios/pull/361) | ios | 0027 | 예 | TP | 예 | 아니요 | FP | `SWIFT-SERVER-TRUST-ACCEPTED` | `SWIFT-SERVER-TRUST-ACCEPTED` |
| [brave-ios-opensearch-insecure-template-urls](https://github.com/brave/brave-ios/pull/7721) | ios | 0026 | 예 | FN | 아니요 | 아니요 | TN | – | – |

## 놓친 이유

- **함수 간 흐름 (2).** Element Android는 중첩 Intent를 `startActivity`를 호출하는 helper로 넘기고,
  Nextcloud Talk는 provider의 표시 이름을 한 함수에서 읽어 다른 함수에서 파일 이름으로 씁니다. APSA의
  흐름 분석은 한 함수 안에 머뭅니다.
- **추가된 적 없는 통제 (5).** `FLAG_SECURE`가 없는 화면 2개(APSA가 검사하지 않는 MASWE-0038), 파일·content
  접근을 기본값으로 둔 WebView, iCloud 백업에서 제외하지 않은 복호화 캐시, 사용자 확인 없는 URL 동작입니다.
  APSA는 있는 설정을 보고하며 없는 통제는 보고하지 않습니다.
- **해당 API 규칙 없음 (3).** RSA PKCS#1 v1.5 복호화 fallback(`kSecKeyAlgorithmRSAEncryptionPKCS1`),
  `SecPolicyCreateBasicX509`로 평가한 서버 신뢰(호스트 이름 없음), 포함 검사 없이 풀어낸 심볼릭 링크
  항목입니다.
- **안전하지 않은 난수 휴리스틱 (2).** `SOURCE-INSECURE-RANDOM`은 약한 생성기의 값이 한 문장 안에서 보안
  관련 이름의 변수에 대입될 때만 보고합니다. 생성기 객체를 한 번 만들어 두고 비밀번호나 PKCE verifier를
  만드는 코드는 놓칩니다.
- **순서와 의도 (2).** 패스코드 확인 전에 URL을 처리하는 문제(VLC)와 http OpenSearch 템플릿을 받아들이는
  문제(Brave)는 동작에 대한 추론이 필요합니다.
- **스캔 실패 (1).** OsmAnd 앱 폴더의 텍스트 입력은 71MB이고 그중 53MB가 번역 XML이라 64MB 입력 스테이징
  한도를 넘습니다. APSA는 이런 감사를 부분 결과로 돌려주지 않고 거부합니다.

## 수정 쪽이 탐지된 이유

FP 4개는 모두 관련 API를 APSA가 모델링하지 않는 가드 뒤에 남긴 수정입니다. 클래스 허용 목록을 둔
`ObjectInputStream` 하위 클래스(NewPipe), 여전히 자체 서명 인증서를 받는 `#if DEBUG` 분기(Telnyx),
프레임과 origin을 확인하게 된 script message handler(Home Assistant), 권한으로 보호하게 된 receiver와 같은
파일에 있는 가변 PendingIntent(Nextcloud Talk)입니다. 마지막 쌍의 취약 쪽 "TP"도 같은 무관한
PendingIntent이며 줄 단위 일치가 아닙니다.

## 한계

24쌍이라 구간이 넓고, 평가 대상 정의는 약점 수준입니다. 7쌍은 없는 통제에 라벨을 붙였는데, 패턴이나 함수
안 흐름 분석기는 이런 경우를 거의 보지 못합니다. 9쌍은 SDK나 라이브러리 코드입니다. 정답은 모델 기반
에이전트가 공개 자료로 만들었고, 두 커밋의 코드와 대조해 확인했지만 두 번째 사람 검토자는 없었습니다.

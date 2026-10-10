# OWASP MASTG v2.0 데모 평가

영어 원문 [MASTG_RESULTS.md](MASTG_RESULTS.md)를 요약한 번역입니다.

[`mastg_demos.py`](mastg_demos.py)는 OWASP MASTG v2.0.0(커밋 `990472d`, 아카이브 SHA-256 고정)의
데모 가운데 결과(통과·실패)를 밝힌 데모로 APSA를 채점합니다. 라벨은 데모의 `kind: fail|pass`,
없으면 Evaluation 절의 "The test fails/passes" 문장에서 가져옵니다. 데모의 테스트가 가리키는
MASWE beta ID를 v1.0으로 변환하고, APSA는 데모의 원본 샘플 소스만 검사합니다. 방법은 첫 실행 전에
모듈 설명에 고정했으며, CC BY-SA 4.0 자료에서는 ID와 결과만 저장합니다.

## 최초 결과

[실행 37942539599](https://github.com/ictechgy/apsa/actions/runs/37942539599)(head `60f1fb5`,
이 데모들에 맞춘 규칙 변경 전):

| 데모 | 개수 |
| --- | ---: |
| 라벨 있음 | 133 |
| 범위 안: TP / FN | 15 / 53 |
| 범위 안: TN / FP | 4 / 1 |
| 평가 안 함(관련 APSA 검사 없음) | 32 |
| 샘플 소스 없음(스크립트·동적 전용) | 38 |
| 라벨 없음 | 14 |
| 엄격 쌍 정답 | 2개 중 0 |

범위 안 recall 22%(68개 중 15), precision 94%(16개 중 15)입니다. 놓친 53개 중 42개는 정적 코드
테스트이며, 외부 저장소 쓰기(MASWE-0002), iOS 평문 통신(0026), 사용자 정의 인증서 검증(0027),
WebView 로컬 파일 접근(0034), 모델링한 sink 밖의 신뢰할 수 없는 데이터 처리(0050)에 몰려 있습니다.
이 데모는 MASTG 테스트용 단일 파일 예시이며 실제 앱의 탐지율을 뜻하지 않습니다. 이후 변경은 개발
작업으로 별도 보고합니다.

## 개발 재실행

블라인드 결과가 아닙니다. 측정 대상 규칙은 최초 결과에서 놓친 데모를 확인한 뒤 추가·조정했으므로,
이 수치는 이미 본 데모에서의 개발 진척입니다. [실행 37947125317](https://github.com/ictechgy/apsa/actions/runs/37947125317)
(head `9f63f84`, `results/2026-10-09-mastg-demos-dev.json`), 같은 고정 아카이브와 방법:

| 데모 | 최초 결과 | 개발 재실행 |
| --- | ---: | ---: |
| 범위 안: TP / FN | 15 / 53 | 26 / 42 |
| 범위 안: TN / FP | 4 / 1 | 4 / 1 |
| 평가 안 함 / 샘플 없음 / 라벨 없음 | 32 / 38 / 14 | 32 / 38 / 14 |
| 엄격 쌍 정답 | 2개 중 0 | 2개 중 0 |

범위 안 recall 38%(68개 중 26), precision 96%(27개 중 26)입니다. 새 TP 11개는 놓친 유형에 추가한
검사에서 나왔습니다. 외부 저장소 쓰기 5개, 모든 인증서·호스트 허용 2개, Java 역직렬화 1개, 평가 없는
iOS 서버 신뢰 2개, 약화된 ATS 예외 1개입니다. 새 FP는 없고 MASTG-DEMO-0060이 유일한 FP입니다.

중간 결과도 기록합니다. MASTG-DEMO-0147은 최초 결과에서 `AST-PENDINGINTENT-MUTABLE`이 데모의 명시적
Intent + `FLAG_MUTABLE`(약점이 아님)을 잡아 TP였습니다. 검사가 Intent 변수의 생성 위치를 따라가게 되자
([실행 37946691836](https://github.com/ictechgy/apsa/actions/runs/37946691836), head `7439ce7`) FN이 됐습니다(25 / 43).
이제 `FLAG_IMMUTABLE` 없는 리터럴 flags도 Android 12 이전 기본값에 따라 mutable로 보므로, flags `0`·
`FLAG_UPDATE_CURRENT`인 암시적 Intent는 잡고 명시적·immutable 호출은 잡지 않습니다.

1.4.0 런타임 후보 `803220d`([실행 37949319562](https://github.com/ictechgy/apsa/actions/runs/37949319562))도
PendingIntent 검사를 플래그 비트 값 기준으로 바꾼 뒤 같은 수치를 냈습니다.

남은 FN 42개는 대부분 아직 규칙이 없는 유형입니다. ATS 밖 iOS 평문 통신(MASWE-0026), WebView 파일
접근(0034), 모델링한 sink 밖의 신뢰할 수 없는 데이터(0050), 인텐트·딥링크·WebView 로딩·UI 노출(0029,
0032, 0035, 0036)입니다.

## 1.5 개발 재실행

1.5는 위에서 놓친 데모의 대부분에 해당하는 약점 검사를 추가합니다. 이 검사는 데모를 읽은 뒤 작성했으므로
이미 본 데모에서의 개발 재실행이며, 1.5의 blind 측정은 [MASWE 라벨 쌍 holdout](BLIND_PAIRS_RESULTS.ko.md)입니다.
[실행 38028133933](https://github.com/ictechgy/apsa/actions/runs/38028133933)은 1.5.0 런타임 `1fac679`(`47ce760`을
통해, `results/2026-10-10-mastg-demos-dev150.json`)를 같은 고정 아카이브와 방법으로 측정했습니다.

| 데모 | 1.4 재실행 | 1.5 재실행 |
| --- | ---: | ---: |
| 평가 대상: TP / FN | 26 / 42 | 52 / 26 |
| 평가 대상: TN / FP | 4 / 1 | 4 / 1 |
| 평가 제외 / 샘플 없음 / 라벨 없음 | 32 / 38 / 14 | 22 / 38 / 14 |
| 엄격한 쌍 정답 | 2개 중 0 | 2개 중 0 |

평가 대상 recall은 67%(78개 중 52개), precision은 98%(53개 중 52개)입니다. 1.5가 약점에 검사를 연결해
10개 데모가 평가 대상에 새로 들어왔습니다. 새 TP 26개의 출처는 생체·로컬 인증(5), 하드코딩된 키 재료(3),
짧은 RSA 키(2), CommonCrypto의 깨진 cipher와 ECB(2), TLS 1.2 미만(2), ATS 밖 iOS 연결(2), 그리고 Android
깨진 cipher, CryptoKit `Insecure` 다이제스트, 네트워크 보안 설정의 사용자 CA, UIWebView, `SQLiteQueryBuilder`를
통한 provider SQL, 앱 내부용 암시적 Intent, provider 표시 이름에서 온 경로 조작, secure coding 없는 keyed
unarchiving, `autoVerify` 없는 App Links, 꺼진 Safe Browsing 각 1개입니다. FP는 여전히 MASTG-DEMO-0060
하나뿐입니다.

남은 FN 26개 중 5개는 MASTG가 MASWE-0034로 분류하지만 APSA는 브리지 규칙을 MASWE-0033에 연결하는
JavaScript 브리지·DOM 데모입니다. 나머지는 APSA에 정적 규칙이 없는 동작입니다(입력 검증 없는 딥링크 처리,
WebView 내비게이션 처리, UI·키보드 노출, 백업 제외, FileProvider 권한 부여, 권한·목적 문자열, 트래픽 속
개인정보, 호스트 이름 검증 없는 `SSLSocket`, 여러 용도로 쓰는 비대칭 키, `@_silgen_name`으로 부른 `rand`,
공격자 쪽 데모 앱).


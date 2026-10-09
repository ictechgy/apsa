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

남은 FN 42개는 대부분 아직 규칙이 없는 유형입니다. ATS 밖 iOS 평문 통신(MASWE-0026), WebView 파일
접근(0034), 모델링한 sink 밖의 신뢰할 수 없는 데이터(0050), 인텐트·딥링크·WebView 로딩·UI 노출(0029,
0032, 0035, 0036)입니다.

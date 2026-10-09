# 독립 취약·수정 소스 쌍 평가

영어가 원본이며 이 문서는 번역입니다. [English](FPFN_RESULTS.md) ·
[정답](fpfn_truth.json) · [평가](fpfn_eval.py) ·
[최초 결과 JSON](results/2026-10-09-fpfn-first.json).

이 개발 평가(미배포, APSA 1.2.0에 포함되지 않음)는 공개 Android·iOS 앱의 실제 보안
수정에서 소스 발견 항목을 측정합니다. 좁은 표본이며 운영 탐지율이 아닙니다.

## 방법

독립 조사 에이전트가 공개 수정 13건을 고르고, 각각의 취약·수정 commit, 해당 파일·
함수·행 범위, 기대 APSA 규칙군을 라벨링했습니다. 11건은 소스 규칙군 범위 안이고
2건은 범위 밖입니다. 모든 commit과 변경 코드를 GitHub API로 확인했으며 스캐너를
실행하거나 읽지 않았습니다. 정답(`fpfn_truth.json`, SHA-256
`229b9070166881b136c765eaa65893dd99b09421464c72d7337b7bce97bf535a`)은 이 소스에 대한
APSA 스캔 전에 `659d948`로 커밋했습니다.

[37911256639 실행](https://github.com/ictechgy/apsa/actions/runs/37911256639)은 각
commit을 GitHub에서 내려받아 symlink 없이 풀고, 라벨된 파일의 최상위 폴더를 APSA로만
스캔했습니다(head `10cc402`). 취약 쪽에서 기대 규칙이 라벨된 파일에 근거를 보고하면
**TP**, 아니면 **FN**입니다. 수정 쪽에서 기대 규칙이 여전히 보고되면 **FP**, 아니면
**TN**입니다. 행 단위 일치(라벨 범위 ±3행)는 따로 기록합니다. upstream 빌드·백엔드·
기기는 실행하지 않았습니다.

## 최초 결과

| 채점 쌍 | TP | FN | FP | TN | 행 단위 TP |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | 5 | 6 | 1 | 10 | 3 |

| 쌍 | 기대 규칙군 | 취약 | 수정 |
| --- | --- | --- | --- |
| SMSSync Twitter OAuth `onReceivedSslError` | WebView SSL 우회 | TP(행) | TN |
| OpenClaw Android canvas bridge(CVE-2026-35643) | JS bridge | TP(행) | FP |
| Tiddloid 편집기 file URL 접근 | WebView 파일 접근 | TP(행) | TN |
| Amaze File Manager `usesCleartextTraffic` | Android cleartext | TP(파일) | TN |
| Wikipedia iOS `NSAllowsArbitraryLoads` | iOS ATS | TP(파일) | TN |
| Home Assistant `MyActivity` WebView URL(CVE-2023-41898) | 신뢰할 수 없는 WebView URL | FN | TN |
| Element X Android 통화 intent URL(CVE-2025-27599) | 신뢰할 수 없는 WebView URL | FN | TN |
| Element X iOS 통화 deep link(CVE-2026-55644) | 신뢰할 수 없는 WebView URL | FN | TN |
| Nextcloud Android `FileContentProvider`(CVE-2021-43863) | raw SQL 연결 | FN | TN |
| Element Android 검증 이벤트 로그 | 민감 로그 | FN | TN |
| OpenClaw iOS relay 자격증명 `UserDefaults` | preferences 토큰 | FN | TN |

범위 밖 2쌍(FairEmail 첨부 경로 순회, Tasks 공유 링크 파일 복사)은 라벨된 파일에서
발견 항목이 없었습니다.

## 놓친 이유

- **파일 간 흐름.** 두 Element X 쌍은 deep link URL이 parser와 navigation 계층을 거친
  뒤 WebView에 로드됩니다. APSA의 untrusted-URL 규칙은 함수 내부 흐름만 봅니다.
- **Home Assistant.** 라벨된 파일에서 부분 문자열 host 검사(`WEBVIEW-HOST-MATCH`)만
  보고했고 신뢰할 수 없는 로드 자체는 보고하지 않았습니다.
- **sink 범위.** Nextcloud 주입은 `SQLiteDatabase.delete`와
  `SQLiteQueryBuilder.appendWhere`에 도달합니다. `AST-SQL-CONCAT`은 `rawQuery`·`execSQL`만
  모델링합니다.
- **데이터 형태.** Element Android 유출은 이벤트 객체 전체를 기록한 Kotlin 템플릿이고,
  OpenClaw iOS 비밀은 인코딩된 설정 구조체 안에 있습니다. 둘 다 패턴 규칙이 찾는
  token·password 이름의 값이 없습니다.
- **가드 기반 수정.** OpenClaw Android 수정은 `addJavascriptInterface`를 유지하고 origin
  검사를 추가했으므로 수정 commit에도 bridge 후보가 남습니다. 라벨러가 이를 예상했습니다.

## 한계

10개 저장소의 11개 채점 쌍으로 일반 재현율·정밀도를 입증할 수 없습니다. 라벨은 조사
에이전트 하나가 만들었습니다. 파일 단위 일치는 같은 파일의 다른 행에 있는 발견도 인정할
수 있으므로 행 단위 일치를 따로 보고합니다. 신뢰할 수 있는 공개 수정 쌍을 찾지 못한
규칙군(ECB, 약한 해시, Keychain 접근성, host allowlist, debuggable, Objective-C WebView
흐름)은 측정하지 않았습니다. 스캔은 [NEXT_ANALYSIS.md](../docs/NEXT_ANALYSIS.md)와
[DEPENDENCY_RESULTS.ko.md](DEPENDENCY_RESULTS.ko.md)에 설명한 파서 적응·의존성 근거를
포함한 개발 브랜치로 실행했습니다.

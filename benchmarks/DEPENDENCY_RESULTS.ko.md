# Gradle 자체 해석 결과와 비교한 의존성 근거

영어가 원본이며 이 문서는 번역입니다. [English](DEPENDENCY_RESULTS.md) ·
[사례](dependency_cases.json) · [Oracle](dependency_oracle.py) ·
[평가](dependency_eval.py).

이 개발 작업(미배포, APSA 1.2.0에 포함되지 않음)은 Gradle version catalog
alias를 실제로 사용하는 빌드 구성과 연결하고, Gradle lockfile을 해석된 빌드
근거로 읽습니다. 소스 선언만으로 출하 라이브러리를 어디까지 식별하는지, lockfile
좌표가 Gradle의 실제 해석과 일치하는지 측정합니다. 취약점 탐지율을 측정하지
않습니다.

## 방법

정답(oracle)은 Gradle 자체입니다. 고정한 공개 앱마다 일회용 runner에서 모든
구성을 잠근 채 앱 모듈을 해석하고(`gradle <app>:dependencies --write-locks`)
lockfile을 기록했습니다. 이 작업에는 APSA를 설치하지 않았습니다. 앱 모듈의 release
runtime classpath에 나타나면 **출하**로 봅니다. benchmark·non-minified baseline
profile variant는 제외합니다. 이 정의는 고정 전, 해당 소스에 대한 APSA 스캔 전에
한 번 좁혔습니다.

각 정답 파일은 APSA가 해당 소스를 스캔하기 전에 커밋했습니다.

| 묶음 | Oracle 실행 | 앱(고정 commit은 `dependency_cases.json`) | 확인 전에 고정한 스캐너 |
| --- | --- | --- | --- |
| holdout-1 | [37906456725](https://github.com/ictechgy/apsa/actions/runs/37906456725) | nowinandroid, mihon, Wikipedia, Fossify Calculator | 최초 구현 |
| holdout-2 | [37907617926](https://github.com/ictechgy/apsa/actions/runs/37907617926) | Pocket Casts, Fossify Gallery, element-x | `a32ad7e`(모듈 역할) |
| holdout-3 | [37908633586](https://github.com/ictechgy/apsa/actions/runs/37908633586) | Nextcloud, Home Assistant | `0bfa345`(명시적 비출하 소비) |

AnkiDroid·Signal·ownCloud는 Gradle 구성이 git 메타데이터를 요구하거나 소스
archive에서 실패했고, Amaze는 NDK 설치가 필요해 제외했습니다. 정답이 없으므로
채점하지 않습니다.

채점 단위는 버전이 있는 catalog 라이브러리 항목입니다. **TP**: APSA가 declared
후보로 표시하고 Gradle도 출하. **FP**: declared이지만 앱 모듈이 출하하지 않음.
**보류**: APSA가 미해결로 유지. 버전 없는(BOM 관리) 항목은 채점 범위 밖입니다.

## 묶음별 최초 결과

| 묶음 | TP | FP | 보류·출하 | 보류·비출하 | 정밀도 | 출하 커버리지 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| holdout-1 | 198 | 22 | 11 | 55 | 90.0% | 94.7% |
| holdout-2 | 90 | 9 | 126 | 77 | 90.9% | 41.7% |
| holdout-3 | 63 | 1 | 82 | 85 | 98.4% | 43.4% |

APSA 1.2.0은 catalog에만 있는 항목을 모두 보류하므로 같은 단위의 declared
커버리지는 0입니다. TP 중 catalog 선언 버전과 Gradle 해석 버전이 다른 경우가
각각 198개 중 15개, 90개 중 2개, 63개 중 1개였습니다. declared 후보는 실제 출하되지
않는 버전을 가리킬 수 있으므로 정확한 대조에는 여전히 해석된 근거가 필요합니다.

각 최초 결과는 결함을 하나씩 드러냈고, 이후 수정은 commit 이력에 남겼습니다.

- holdout-1: 빌드 도구(`kotlin-dsl` 빌드), Android test 모듈, 테스트 지원 모듈을
  출하로 셌습니다.
- holdout-2: 모듈 소비 규칙이 benchmark·coverage 도구가 참조한 application 모듈을
  제외해 Pocket Casts 라이브러리 107개를 모두 가렸습니다.
- holdout-3: Home Assistant는 모든 모듈의 lockfile을 커밋합니다. APSA가 이를 사용해
  catalog 항목이 declared가 아닌 대체(superseded) 상태가 되었습니다(보류 77개).
  library 모듈 lockfile을 exact로 취급하던 점은, 다른 출하 모듈이 그 모듈을 소비한다는
  근거가 있으면 후보로 남기도록 고쳤습니다.

## 정답을 본 뒤의 개발 재실행

[37909811466](https://github.com/ictechgy/apsa/actions/runs/37909811466) 실행은 현재
브랜치를 세 묶음 모두에 채점합니다. 블라인드 결과가 아닙니다.

| 묶음 | TP | FP | 보류·출하 | 정밀도 | 출하 커버리지 |
| --- | ---: | ---: | ---: | ---: | ---: |
| holdout-1 | 198 | 3 | 11 | 98.5% | 94.7% |
| holdout-2 | 194 | 27 | 22 | 87.8% | 89.8% |
| holdout-3 | 63 | 1 | 82 | 98.4% | 43.4% |

남은 오탐:

- `coreLibraryDesugaring`(앱마다 1개). desugaring 라이브러리 코드는 dex에 포함되지만
  runtime classpath 좌표가 아니어서 oracle이 출하로 세지 않습니다.
- holdout-2의 27개 중 19개는 Pocket Casts의 **wear**·**tv** application 모듈에서
  나왔습니다. 같은 저장소의 다른 APK가 출하하는 라이브러리이며, oracle은 휴대폰 앱만
  측정합니다. 모듈을 선택하지 않은 소스 스캔은 저장소의 모든 앱을 합칩니다.
- precompiled convention script로 소비되는 element-x annotation processor·테스트
  유틸리티 모듈. 모듈 그래프가 이 script를 읽지 않습니다.

보류는 주로 BOM, 전이 의존성, 그리고 커밋된 lockfile이 정확히 해석하는 Home
Assistant의 대체 항목입니다.

## Lockfile 근거

oracle lockfile을 앱 모듈에 두면 아홉 앱 모두에서 APSA의 exact 좌표가 Gradle의 출하
좌표와 같습니다: 256, 378, 315, 179, 402, 214, 412, 384, 372개, 누락·초과 없음.
Home Assistant가 공개한 lockfile을 그대로 쓰면 앱 좌표 372개가 모두 exact입니다.
APSA는 그 밖에 서로 다른 exact 좌표 149개를 더 보고합니다. wear(59개 항목)·
automotive(2) application 모듈과 test·library 역할을 인식하지 못한 `testing-unit`(77)·
`microwakeword`(22) 모듈에서 나왔습니다.

## 고정된 6개 앱 재실행

[37909997903](https://github.com/ictechgy/apsa/actions/runs/37909997903) 재실행에서
기존 32개 의존성·CVE 단위는 8 TP / 0 FP / 0 FN / 19 TN / 정당한 보류 5로 유지됩니다.
K-9의 catalog 전용 선언 2개(jsoup 1.15.4, okio 3.7.0)는 `app/core/build.gradle.kts`의
`implementation` 참조로 declared 후보가 되었습니다. 조회 결과가 고정된 "unaffected"
라벨과 일치해 선택한 실제 앱 CVE 경로는 1 TP / 3 TN, 보류 0이 됩니다. 라벨을 본 뒤의
개발 재실행이며 최초 요약과 과거 결과 바이트는 바꾸지 않습니다. declared 후보는 여전히
출하 버전을 증명하지 않습니다.

## 한계

declared 후보는 대조에서 `candidate` 상태를 유지합니다. variant 선택, 충돌 해석,
substitution 규칙, included build, Kotlin Multiplatform target, 동적 의존성 표기는
평가하지 않았습니다. oracle은 실행한 upstream 빌드 스크립트를 신뢰합니다. 각 1개
commit의 앱 9개는 좁은 표본이며 일반 정확도를 입증하지 않습니다.

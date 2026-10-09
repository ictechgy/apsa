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

APSA 1.2.0은 설계상 catalog에만 있는 항목을 모두 보류하므로 같은 단위의 declared
커버리지는 0입니다. 이 기준값은 코드에서 따른 것이며 다시 측정하지 않았습니다. TP 중 catalog 선언 버전과 Gradle 해석 버전이 다른 경우가
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
- holdout-2의 27개 중 17개는 Pocket Casts의 **wear**·**tv** application 빌드
  스크립트에서 나왔습니다. 같은 저장소의 다른 APK가 출하하는 라이브러리이며, oracle은
  휴대폰 앱만 측정합니다. 모듈을 선택하지 않은 소스 스캔은 저장소의 모든 앱을 합칩니다.
  2개는 루트 빌드 스크립트의 `implementation` 참조(`leakcanary`, debug 전용 설정으로
  보임)와 `modules/services/qr`(`zxing`)에서 나왔습니다.
- precompiled convention script로 소비되는 element-x annotation processor·테스트
  유틸리티 모듈. 모듈 그래프가 이 script를 읽지 않습니다.

보류는 주로 BOM, 전이 의존성, 그리고 커밋된 lockfile이 정확히 해석하는 Home
Assistant의 대체 항목입니다.

## Lockfile 근거

oracle lockfile을 앱 모듈에 두면 아홉 앱 모두에서 APSA의 exact 좌표가 Gradle의 출하
좌표를 모두 포함합니다(256, 378, 315, 179, 402, 214, 412, 384, 372개). 여덟 앱에서는
초과도 없습니다. 이는 같은 Gradle 출력을 거의 같은 구성 필터로 읽는 파서 일관성
검사이며 해석 결과에 대한 독립 근거가 아닙니다. Home Assistant가 공개한 lockfile을
그대로 쓰면 앱 좌표 372개가 모두 exact입니다.
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

## 리뷰 후속 수정(개발, 재블라인드 아님)

이 브랜치의 독립 코드 리뷰는 역할을 인식하지 못한 모듈의 lockfile이 여전히 `exact`
좌표(따라서 `version-affected` 발견)를 만들 수 있고, 대체가 패키지 이름만으로 저장소
전체에 적용되며, 부분 입력이 비출하 판단으로 이어질 수 있음을 찾았습니다. 이제 스캐너는
application 모듈 lockfile만 exact로 취급하고, 선언한 모든 모듈이 그 application이거나
그 application이 출하용으로 소비하는 모듈일 때만 declared 후보를 대체합니다. 소비 관계로
모듈을 제외하려면 library 플러그인 근거와 모든 빌드 스크립트 읽기가 필요하며,
`constraints` 블록과 `apply false` 플러그인 줄은 무시하고, OSV 조회 예산에서 exact 좌표를
먼저 처리합니다. oracle 워크플로는 upstream 빌드 코드 실행 전에 archive 해시를
고정합니다. 이 수정 이후 재실행은 아래 실행 ID로 기록합니다.

[37913317319](https://github.com/ictechgy/apsa/actions/runs/37913317319) 재실행(head
`e1f5eee`, 블라인드 아님)에서 holdout-1·2는 변하지 않았습니다. holdout-3에서는 convention
plugin이 선언한 Home Assistant catalog 항목이 더 이상 일괄 대체되지 않아 TP 58, FP 2, 출하
보류 19가 되었고, 묶음 전체는 TP 121, FP 2, 출하 보류 24(정밀도 98.4%, 출하 커버리지
83.4%)입니다. 커밋된 lockfile을 쓰면 앱 좌표 372개는 그대로 exact이며, 추가 exact 좌표는
wear(59)·automotive(2) application에서만 나옵니다. 고정된 6개 앱 재실행
[37913317339](https://github.com/ictechgy/apsa/actions/runs/37913317339)은 변하지
않았습니다.

2차 리뷰는 lockfile이 있는 앱과 없는 앱이 공유하는 모듈이 여전히 대체될 수 있고, 플러그인
감지가 `version "…" apply false`를 놓치며 일반 플러그인 ID 문자열에도 반응함을 찾았습니다.
이제 declared 후보는 선언 모듈을 출하할 수 있는 모든 앱(인식한 application과 다른 모듈이
소비하지 않는 모듈)이 해당 패키지를 해석했을 때만 대체합니다. 플러그인 감지는 적용 구문만
읽고, version이 붙은 `apply false`를 인식하며, library 플러그인 근거를 우선합니다.

| 결과 파일 | 생성 실행 | head commit |
| --- | --- | --- |
| `results/2026-10-09-dependency-first-holdout1.json` | [37907202313](https://github.com/ictechgy/apsa/actions/runs/37907202313) | `6a86b95` |
| `results/2026-10-09-dependency-first-holdout2.json` | [37908373608](https://github.com/ictechgy/apsa/actions/runs/37908373608) | `36213e0` |
| `results/2026-10-09-dependency-first-holdout3.json` | [37909298008](https://github.com/ictechgy/apsa/actions/runs/37909298008) | `c24d1c3` |
| `results/2026-10-09-dependency-development-rerun.json` | [37909811466](https://github.com/ictechgy/apsa/actions/runs/37909811466) | `8de1758` |
| `results/2026-10-09-dependency-review-rerun.json` | [37913317319](https://github.com/ictechgy/apsa/actions/runs/37913317319) | `e1f5eee` |
| `results/2026-10-09-dependency-frozen-replay.json` | [37909997903](https://github.com/ictechgy/apsa/actions/runs/37909997903) | `ed02049`(패키지 버전 1.2.0 표기) |

## 한계

declared 후보는 대조에서 `candidate` 상태를 유지합니다. settings 파일의 사용자 지정
`projectDir` 재매핑은 읽지 않으므로 재매핑된 모듈의 lockfile은 후보로 남습니다. variant 선택, 충돌 해석,
substitution 규칙, included build, Kotlin Multiplatform target, 동적 의존성 표기는
평가하지 않았습니다. oracle은 실행한 upstream 빌드 스크립트를 신뢰합니다. 각 1개
commit의 앱 9개는 좁은 표본이며 일반 정확도를 입증하지 않습니다.

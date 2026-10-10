# 운영 가이드

APSA (앱사)는 팀이 권한을 가진 앱·소스·테스트 빌드를 검사하는 로컬 도구입니다. 저장 위치는 `--home PATH`, `QUAYGATE_HOME`, `MOBILE_AUDIT_HOME`, 기본 `~/.local/share/mobile-audit` 순으로 선택합니다. 앱 파일·보고서·기기 캡처가 민감할 수 있으므로 팀별 저장소 권한과 보관 기간을 정하십시오. MCP stdio는 클라이언트가 실행하는 로컬 프로세스이며 제품 자체의 모델 API 키가 필요하지 않습니다. 연결한 AI 클라이언트는 받은 분석 메타데이터를 모델 서버로 전송할 수 있으므로 팀의 모델 사용 정책에 따라 연결하십시오. 로컬 실행이 프로젝트의 오픈소스 공개를 뜻하지 않으며 공개 라이선스는 아직 지정하지 않았습니다.

## 설치와 도구 확인

```sh
uv sync --locked --extra dev
uv run --locked apsa doctor --json
```

정적 검사는 설치된 Python 의존성만으로 오프라인 실행됩니다. 문법 라이브러리는 패키지에 포함되며 검사 시 내려받지 않습니다. `scan --online`, `intel sync`, `intel watch`, 공개 문서 요청은 네트워크를 사용합니다. OSV 조회에는 발견한 패키지 이름·버전을 전송합니다. 정적 검사 입력 소스와 앱 바이너리를 피드 제공자에게 업로드하지 않습니다.

`make install-local`은 Python 3.12.13과 잠긴 런타임 제약으로 editable 개발 도구를 설치합니다. 소스 편집이 실행에 바로 반영되는 개발 모드입니다. 배포 검증은 아래의 깨끗한 wheel 설치 절차를 사용하십시오.

Android 도구는 `PATH`를 먼저 확인한 뒤 `ANDROID_SDK_ROOT`, `ANDROID_HOME`, `~/Library/Android/sdk`, `~/Android/Sdk`에서 찾습니다. SDK의 `platform-tools/adb`, `emulator/emulator`, `cmdline-tools/latest/bin/*`가 대상입니다. `doctor`는 SDK 다운로드·라이선스 동의·기기 부팅을 수행하지 않습니다. 런타임 검사는 승인된 기기 ID를 명시하고 테스트 앱의 설치·실행·상태 변경을 검토한 뒤 실행하십시오. Android 비디버그 앱은 `run-as` 기반 샌드박스 확인이 제한됩니다. iOS 런타임은 macOS의 Xcode `xcrun simctl`과 부팅된 시뮬레이터가 필요합니다. 실제 iOS 기기는 지원 범위에 포함되지 않습니다.

## 저장소, 이전, 백업과 복구

`audit.sqlite3`는 WAL 모드이며 보고서 JSON은 `reports/`, 인텔 원본의 내용 해시별 스냅샷은 `intel-records/`에 보관합니다. 저장소 디렉터리는 생성 시 0700, DB는 0600입니다. 이미 존재하는 디렉터리의 운영 권한도 직접 확인하십시오.

DB를 열면 트랜잭션으로 현재 스키마(`PRAGMA user_version=2`)까지 이전합니다. 같은 보고서 ID에 다른 내용을 덮어쓰지 않습니다. 보고서를 최신 인텔로 재평가하면 새 보고서와 부모 연결을 만듭니다. 인텔 갱신도 이전 원본 스냅샷을 보존합니다. DB 이전 실패 시 트랜잭션은 롤백되지만 파일 시스템까지 하나의 원자적 트랜잭션이라는 보장은 없습니다. 업그레이드 전에 전체 홈을 백업하십시오.

안정된 백업은 watch와 모든 백그라운드 작업을 멈춘 뒤 홈 전체를 복사하는 방식입니다. 실행 중 DB만 복사하면 WAL 변경을 놓칠 수 있습니다. DB 백업이 필요하면 SQLite 백업 API를 사용하십시오. 아래 명령은 사용자가 정한 저장소와 새 백업 파일만 읽고 씁니다.

```sh
python - /absolute/audit-home/audit.sqlite3 /absolute/backup/audit.sqlite3 <<'PY'
import sqlite3, sys
with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as source:
    with sqlite3.connect(sys.argv[2]) as destination:
        source.backup(destination)
PY
```

이 DB 백업과 별도로 `reports/`, `intel-records/`, 설정·작업 파일도 보관하십시오. 복구는 작업을 모두 중지하고 현재 홈을 별도 보존한 후 백업 홈을 새 위치에 복원하여 `--home`으로 검증합니다. 복원한 이전 작업을 자동 재개한다고 가정하지 마십시오. 이전 버전으로 롤백할 때는 그 버전에서 만든 백업을 함께 복원하십시오. 새 스키마를 오래된 바이너리로 읽는 호환성은 보장하지 않습니다.

```sh
apsa reports verify --home /absolute/restored-home --json
```

검증은 DB 보고서 내용의 저장 해시와 내보낸 JSON을 비교합니다. 실패하면 종료 코드 3입니다. 내용 해시는 변경 감지를 위한 것이며 발행자 서명·외부 공증이 아닙니다. DB와 해시를 함께 바꿀 수 있는 공격자까지 인증하지 않습니다.

## 유한 검사와 지속 작업

기본 입력 제한은 파일 8 MiB, 소스 합계 64 MiB, 12,000개 파일, 아카이브 512 MiB입니다. AST 추가 제한은 파일 2 MiB, 합계 32 MiB, 파일당 100,000개 노드·전체 500개 발견입니다. 큰 DEX·Mach-O와 캡처에도 별도 제한이 있습니다. 제한으로 빠진 범위는 경고와 `partial` 또는 `not-run`으로 보고하며 보안 통과로 해석하지 않습니다. 소스 폴더가 합계·파일 수 한도를 넘어도 감사를 거부하지 않습니다. 앱 코드·설정(Kotlin·Java·Swift·Objective-C·Dart·JS/TS, Gradle·잠금 파일, 매니페스트, `res/xml`, plist, `google-services.json` 등), 기타 출하 텍스트(기본 리소스·JSON·YAML), Android 번역·한정자 values(`res/values-*`), 테스트 순으로 스테이징하고, 한도에 들지 못한 파일은 종류별 파일 수·바이트로 `inventory.input_snapshot.omitted`에 남깁니다. 디렉터리 항목 100,000개(트리 전체, 이름순)·깊이 64단계를 넘는 부분은 읽지 않습니다. 어느 경우든 감사는 `partial`이며, 앱 코드·설정이나 기타 출하 텍스트가 빠지면 not-applicable coverage도 `partial`이 되어 필수 규칙이 통과하지 않습니다. 읽기·복사에 실패한 파일도 그 파일만 생략합니다. 스테이징 시간 한도(90초) 초과, 입력 루트 변경, 복사 중 파일 교체만 감사를 거부합니다. 잘린 결과를 피하려면 소스 범위를 나누거나 실제 빌드 SBOM을 함께 제공하십시오.

소스 폴더 열거·파일 상태 확인·읽기가 실패하면 경고와 불완전한 fingerprint/coverage로 남고, 읽을 수 있는 다른 파일의 근거는 보존합니다. 지원하는 파일을 하나도 읽지 못하면 명시적인 실행 오류로 종료합니다. 의도적으로 제외한 폴더와 심볼릭 링크는 계속 검사 대상에서 제외합니다. iOS 저장소 캡처의 열거·파일 확인·읽기 실패는 `not-run`이며 canary 삭제 통과로 바뀌지 않습니다. 캡처 오류에 포함된 canary 값도 label로 가립니다.

파서는 DB·네트워크에 접근하지 않는 별도 프로세스로 실행합니다. 사용자당 동시 파서 2개, 벽시계 90초, CPU 45초, RSS 1 GiB, 출력 32 MiB 제한이 있습니다. Linux에는 주소 공간 2 GiB 제한도 적용합니다. 이 경계는 자원 제약이며 완전한 OS 샌드박스는 아닙니다. 신뢰할 수 없는 앱은 별도 격리 호스트에서 검사하십시오.

```sh
apsa scan /absolute/source --background --home /absolute/audit-home --json
apsa jobs list --home /absolute/audit-home --json
apsa jobs status JOB_ID --home /absolute/audit-home --json
apsa jobs cancel JOB_ID --home /absolute/audit-home --json
```

홈별 활성 작업은 최대 2개입니다. CLI가 반환한 ID로 `queued/running/completed/failed/cancelled/interrupted` 상태를 확인합니다. `requested_target`은 요청한 경로, `target`은 대기열 등록 시 정규화해 고정한 검사 대상입니다. 워커가 시작할 때 고정한 경로가 다른 곳으로 연결되면 검사를 거부합니다. 소스 파일의 내용까지 대기열 등록 시 복제하는 방식은 아니며, 보고서 해시는 실제 검사한 입력을 나타냅니다. 시작에 실패한 대기 작업이나 사라진 워커는 `interrupted`로 정리합니다. 취소는 PID·시작 시간·작업 ID를 확인한 워커에 신호를 보내며 프로세스 정리는 해당 워커의 종료 처리에 따릅니다. 이미 수행한 앱 설치나 앱 상태 변경을 되돌리는 기능은 아닙니다. 백그라운드 검사는 완료한 보고서를 별도로 내보내고 정책 평가합니다.

## 정책, 기준 보고서와 CI

```sh
apsa policy init --out apsa.toml
apsa scan /absolute/source --policy apsa.toml --home /absolute/audit-home --json
apsa policy evaluate latest --policy apsa.toml --baseline REPORT_ID --home /absolute/audit-home --json
```

기본 정책은 `configuration-confirmed`, `runtime-confirmed`, `version-affected`만 임계값에 포함하며 `candidate`는 명시적으로 추가합니다. `only_new=true`는 실제 기준 보고서가 필요합니다. 동일한 발견도 심각도 또는 증거 상태가 상승하면 새 발견으로 평가합니다. 기준 보고서를 바꾸는 결정은 검토 기록으로 남기십시오.

예외는 정확한 발견 ID, 비어 있지 않은 이유, `YYYY-MM-DD` 만료일이 필요합니다. 만료일은 UTC 해당 날짜까지 유효하며 만료·잘못된 예외는 검사를 `incomplete`로 만듭니다. `required_rules`는 `checked` 또는 `not-applicable`만 인정하며, 미실행·부분 실행·단순 관측(`observed`)은 통과를 막습니다. 예를 들어 `RUNTIME-DEEPLINK`는 URL 요청 성공만으로 만족하지 않고 대상 앱의 전달 marker 검증이 필요합니다. 전달 확인은 별도의 인증 검증을 대신하지 않습니다. 기본적으로 명시적인 `partial`도 통과를 막지만 계획만 존재하는 런타임 항목 전체를 자동 실패시키지 않습니다. 실시간 인텔을 필수로 삼으면 `require_fresh_intel`과 `required_feeds`를 명시하십시오.

| 코드 | 의미 |
| --- | --- |
| 0 | 정상 처리 또는 정책 통과 |
| 1 | 실행 실패 |
| 2 | 잘못된 사용법·입력 설정 |
| 3 | 정책 불완전, 보고서 검증 실패, 인텔 동기화 실패 등 |
| 4 | 정상 평가 결과가 정책 임계값을 초과 |
| 130 | 사용자 인터럽트 |

JSON의 `ok=true`는 종료 코드 4도 포함하므로 CI는 `exit_code`와 정책 `state`를 함께 확인하십시오. 정책 없는 일반 정적 검사의 종료 코드 0만으로 모든 범위를 검사했다고 판단하지 마십시오.

## 인텔 폴링과 장애

```sh
apsa intel sync --home /absolute/audit-home --json
apsa intel status --home /absolute/audit-home --json
apsa intel watch --interval 900 --home /absolute/audit-home
```

watch는 기본 900초, 최소 60초 주기로 공개 피드를 폴링합니다. `--cycles`로 유한 실행할 수 있고 0은 인터럽트까지 실행합니다. 푸시 스트림이나 공개 전 제로데이 탐지를 보장하지 않습니다. 기본 최근 벤더 공지는 소스별 3건이며 `--limit 1..50`으로 조절합니다. CVE 변경 목록은 제한된 배치로 처리하고 보류 큐를 저장합니다. 벤더 우선 항목과 오래된 FIFO 항목에 각각 처리 자리를 배정하여 지속 유입이 과거 항목을 밀어내지 않게 합니다.

404·429·일시적인 네트워크 오류는 완료로 처리하지 않고 재시도 시간·시도 횟수와 함께 보류합니다. 백오프는 제한되며 다음 폴링에서 기한이 된 항목을 처리합니다. 실패한 새 응답이 이전 정상 캐시를 지우지 않습니다. `intel status`의 `attempted/succeeded/status/error/pending/stale`을 확인하십시오. 마지막 성공이 24시간을 넘거나 성공 기록이 없으면 stale입니다. 캐시가 있다는 사실과 현재 피드가 정상이라는 사실을 구분하고, 최신성이 필요한 CI는 정책에서 강제하십시오.

## 장애 대응과 업데이트

오류가 나면 작업 ID, 보고서 ID, 제품·Python·OS·SDK 버전, 입력 해시, `doctor`, `intel status`, 검증 결과를 보존합니다. 보고서·캡처의 앱 비밀과 원본 소스를 공개 이슈에 그대로 첨부하지 마십시오. 파서 충돌·한도 초과는 부분 결과를 승인하는 대신 입력 범위를 줄여 재현하고 해당 규칙의 coverage를 확인합니다. DB 검증 실패는 변경을 중단하고 별도 복제본에서 조사합니다.

잠금 파일·인터프리터·빌드 도구를 변경하면 전체 테스트와 독립 corpus, 깨끗한 설치 smoke를 다시 실행합니다. 패키지는 새 가상 환경에 설치하여 `doctor`와 `reports verify`를 수행한 뒤 클라이언트의 실행 경로를 전환합니다. 전역 모델 설정은 자동 변경하지 않습니다. 이전 wheel·SHA256·해당 버전 홈 백업을 보관하면 실행 경로와 홈을 함께 되돌릴 수 있습니다.

## 로컬 배포 검증

```sh
make test benchmark
make release RELEASE_OUT=/absolute/new-release-directory
# 필요한 캐시가 모두 준비된 경우에만:
uv run --locked --extra dev python scripts/release.py --offline --out /absolute/new-offline-release-directory
```

릴리스 스크립트는 허용한 소스·문서·테스트 경로만 임시 디렉터리로 복사합니다. `.omx` 검증 증거, 개인 앱·홈·캐시는 패키지에 포함하지 않습니다. 현재 checkout을 수정하거나 기존 결과를 덮어쓰거나 배포하지 않습니다. 출력에는 wheel/sdist, 해시 목록, 잠긴 런타임·빌드 요구사항, 설치된 의존성 CycloneDX SBOM, 실제 메타데이터·라이선스 원문, 검사 manifest가 포함됩니다. 프로젝트 자체의 공개 라이선스는 지정하지 않습니다.

uv 0.12.1과 빌드 도구의 버전·wheel 해시, `SOURCE_DATE_EPOCH`을 고정합니다. 같은 스테이징 입력·호스트·인터프리터에서 두 번 만든 wheel/sdist가 같은지 검사하고 checkout 밖의 새 환경에 해시 검증으로 설치하여 help/version/doctor/오프라인 소스 검사/보고서 검증을 실행합니다. 첫 설치에는 uv·CPython·PyPI wheel 다운로드가 필요합니다. `--offline`은 기존 캐시만 사용하며 Python을 자동 내려받지 않습니다. 배포 의존성은 binary wheel만 허용하므로 대상 플랫폼용 wheel이 없으면 실패합니다.

동일한 두 빌드 검증은 다른 OS·Python·SDK 사이의 바이트 일치를 뜻하지 않습니다. 런타임 SBOM도 생성 호스트의 마커에 해당하는 Python 배포본만 포함합니다. OS 라이브러리·Android SDK·Xcode·기기 이미지·검사 대상 앱의 의존성은 별도입니다. CI runner 이미지는 가변이고 인터프리터 배포본은 별도 공급망이므로 업데이트 시 재검증하십시오. 개발 검사인 Pyright는 Node 런타임도 사용합니다. CI는 runner의 Node 버전을 기록하지만 고정하지 않으며 Node 없는 로컬 환경은 추가 다운로드가 필요할 수 있습니다. 제품 런타임·릴리스 빌드는 Node를 필요로 하지 않습니다. SHA256은 무결성 확인이며 릴리스 서명은 아직 제공하지 않습니다. `SHA256SUMS` 검증에 사용할 신뢰 가능한 해시를 별도로 보관하십시오.

## 1.0.2 소비자 기본값

`scan`은 inventory뿐 아니라 coverage·요청한 온라인 조회·최근 runtime의 부분 상태를 종료 코드 3에 반영합니다. 백그라운드 `completed`는 작업 종료 상태이며 `audit_incomplete`로 감사 범위 완결성을 별도 표시합니다.

`intel watch`는 기본적으로 저장한 인벤토리와 캐시를 대조하고 결과·coverage·피드 상태가 달라질 때만 새 이력을 저장합니다. 의존성의 OSV 재조회는 `--online` opt-in입니다. 한 보고서의 무결성 오류는 `reaudit_errors`에 남고 다른 대상의 재평가는 계속합니다. CVE 수집 신선도와 처리 대기열을 분리하되 기본 CI 정책은 처리 대기열·재시도 실패를 통과시키지 않습니다.

DEX 분석의 기본 100,000개 메서드·1,000,000개 명령어와 파서 CPU·RSS 제한은 유지합니다. 초기 inventory 단계의 중복 DEX 파싱은 제거했습니다. 대형 실제 앱에서 완전 커버리지를 보장하지 않으며 제한 도달은 incomplete입니다. 해당 규모의 실측과 제한 조정은 별도 검증 사항입니다.

동일 런타임 assertion의 확정적인 재관찰은 기존 발견을 교체합니다. 같은 시나리오의 다른 assertion이 inconclusive이면 그 미확인 증거는 보존하며, 필요한 전환·전달 검증이 실패하면 과거 발견을 통과로 정리하지 않습니다. 반복된 실패의 안정적인 finding ID는 중복 저장하지 않습니다.

앱 ZIP은 상위 폴더가 있어도 최외곽 `.app/Info.plist`를 메인 설정으로 선택하며, Watch 앱·프레임워크·확장 설정은 내장 증거로 보존합니다. Finder의 `__MACOSX`·AppleDouble 파일은 앱 설정이 아니므로 제외합니다. 메인 설정을 리소스보다 먼저 읽고, 리소스 한도 초과는 부분 검사로 기록합니다. 일반 소스 ZIP의 유일한 느슨한 `Info.plist`는 소스 설정 증거이며 실제 설치 앱이나 바이너리 일치를 증명하지 않습니다. APK·IPA·시뮬레이터 .app·앱 ZIP 안에 포함된 다른 플랫폼의 설정·예제 소스는 해당 빌드의 앱 식별자와 플랫폼을 바꾸지 않습니다. APK의 메인 매니페스트는 루트 AndroidManifest.xml이며, assets의 동명 파일은 앱 설정으로 처리하지 않습니다. 프레임워크·확장·리소스 번들 내부의 .app은 외곽 앱으로 승격하지 않습니다. 앱 ZIP은 선택된 외곽 앱 안의 iOS 설정만 보존합니다.

## APSA 1.0.3 리네이밍

제품·CLI·배포 패키지·MCP·스킬의 기본 이름은 APSA/apsa입니다. `quaygate`와 `mobile-audit` 진입점, 이전 resource URI는 호환됩니다. `APSA_HOME` → `QUAYGATE_HOME` → `MOBILE_AUDIT_HOME` 순서로 명시한 데이터 경로를 선택합니다. 기본 `~/.local/share/mobile-audit` 경로를 유지하므로 리네이밍만으로 이력이 새 데이터베이스로 갈라지지 않습니다. 사용자 정책 파일 경로는 자동 변경하지 않으며 새 `policy init`의 기본 파일명만 `apsa.toml`입니다.

`apsa skill install`은 새 기본 스킬을 설치합니다. 알려진 과거 기본 Quaygate/Mobile Audit 스킬도 `--name quaygate`/`--name mobile-audit`로 업데이트할 수 있으며 사용자 수정본은 보존합니다.

격리된 CI에서 `APSA_PARSER_LOCK_DIR`와 `APSA_DEVICE_LOCK_DIR`를 새 private 임시 디렉터리로 지정할 수 있습니다. 동일한 호스트에서 동시 작업을 조율할 프로세스는 같은 잠금 경로를 사용해야 합니다. 기본 사용자 홈과 감사 데이터 위치는 바꾸지 않습니다.

## 1.1 모델·팀 워크플로

context와 MCP `reports_get`은 기본 20개 항목·64 KiB의 UTF-8 JSON 페이지를 반환합니다. CLI envelope와 MCP 전송 framing은 추가 크기입니다. 응답의 `partial_response`를 감사의 `audit_incomplete`와 혼동하지 마십시오. `latest`를 한 번 해석한 뒤 반환된 보고서 ID, section, 필터를 유지하고 `page.next_cursor`를 따라 읽습니다. 용량 때문에 생략된 인덱스는 표시하며 원본은 로컬 보고서 내보내기에 보존됩니다.

`reports export --format baseline`에는 승인자와 승인 참조가 필요합니다. 반환된 SHA-256은 별도로 검토된 CI 설정에 고정하고 `--baseline-file`과 `--baseline-sha256`으로 사용합니다. CI에서 내려받은 파일 자체로 기대 해시를 계산하면 승인 근거가 되지 않습니다. 승인 정보는 기록된 주장이고 해시는 무결성 확인이며, 서명이나 승인자 인증을 제공하지 않습니다. MCP 내보내기는 허용 root 아래 이미 존재하는 부모 폴더에 새 파일만 생성하며 덮어쓰지 않습니다.

`scan --policy --out`은 `<보고서 경로>.decision.json`에 정규화한 정책, 보고서·정책 해시, 기준선 승인 출처, 예외와 판정 사유를 저장합니다. `--decision-out`으로 별도 경로를 지정할 수 있습니다. 소스는 `--source-module`과 그 모듈 기준의 `--configuration`으로 명시하되 빌드 시스템의 variant 병합은 하지 않습니다. 자세한 계약은 영문 원본 [MODEL_WORKFLOWS.md](MODEL_WORKFLOWS.md)를 참고하십시오.

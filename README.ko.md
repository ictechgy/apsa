# APSA (앱사)

**근거 중심의 Android·iOS 보안 감사 도구.**

[English](https://github.com/ictechgy/apsa/blob/main/README.md) · [한국어](https://github.com/ictechgy/apsa/blob/main/README.ko.md)

영문 README가 원본입니다. 이 문서는 영문 원본을 기준으로 작성한 한국어 번역입니다.

APSA는 개발자와 보안팀이 자기 모바일 앱을 감사하는 도구입니다. 소스 코드와 APK·IPA 빌드를 검사하고, 공개 취약점 정보를 대조하며, 근거·검사 범위·보고서 이력을 함께 관리합니다. CLI, 터미널 UI, MCP, 재사용 가능한 스킬에서 같은 감사 엔진을 사용합니다.

영어 발음은 **“ap-sah”**, 한글 이름은 **앱사**입니다. “앱 + 감사”를 연결한 이름이며 **App Security Audit**라는 의미도 담았습니다. 기존 Quaygate 린트 엔진과 Mobile Audit 작업 흐름을 한 패키지에 통합했습니다.

APSA 1.1은 모델 보고서의 제한된 페이지 조회, 승인된 휴대형 기준선, 정책 판정 내보내기, 소스 모듈·설정 선택을 제공합니다. 계약과 예제는 영문 원본 [모델·팀 워크플로](docs/MODEL_WORKFLOWS.md), 이후 분석 단계는 [릴리스 순서](docs/ROADMAP.md)를 참고하십시오.

미지원 언어가 혼합된 소스와 잘린 패턴 결과는 불완전 검사로 표시합니다. Gradle 선언 버전은 실제 빌드에서 확인되기 전까지 후보이며, OS-CVE는 최근 공지 범위만 대조하므로 피드가 최신이어도 역사적 커버리지를 충족하지 않습니다.

## 검사 범위

| 영역 | 제공하는 검사 |
| --- | --- |
| 소스 코드 | Java·Kotlin·Swift AST 분석, WebView·딥링크 패턴, Manifest·Info.plist·저장소·의존성 검사 |
| Android 빌드 | DEX 호출·상수 흐름, 리소스·네트워크 설정, exported 컴포넌트·provider, 서명 블록·v1 인증서 근거, ELF 하드닝 |
| iOS 빌드 | Mach-O 헤더, 제한적인 entitlement·설정 검사(내장 XML entitlement, ATS 예외, provisioning 지표), PIE·카나리·문자열 근거 |
| 공개 취약점 정보 | Apple·Android 공지, CVE, CISA KEV, OWASP 가이드, OSV 의존성 대조 |
| 보고서와 CI | SQLite 이력, 비교·재평가, JSON·Markdown·SARIF 내보내기, 필수 검사 범위, 만료일이 있는 예외 |
| 런타임 | 소유한 Android 테스트 앱과 iOS 시뮬레이터 앱의 준비된 시나리오. 실제 iOS 기기는 미지원 |
| 모델 연결 | stdio MCP 도구·리소스와 패키지 스킬. 특정 모델 제공자나 LLM API 키는 필수가 아님 |

발견 항목은 `candidate`, `configuration-confirmed`, `version-affected`, `runtime-confirmed` 근거를 구분합니다. `coverage`와 경고가 실제 실행한 범위를 표시합니다. 서명 블록의 존재가 서명 진위를 증명하지 않으며, 영향을 받는 의존성 버전이라고 해서 악용 가능성이 입증된 것은 아닙니다. 발견 항목이 없더라도 앱 전체가 안전하다고 판단할 수 없습니다.

OWASP 매핑은 관련 검사를 설명합니다. APSA는 MASVS 준수를 인증하거나 MASTG의 모든 테스트를 구현하지 않습니다. 공개 공지로 미공개 제로데이를 알아낼 수 없으며, 앱 파일만으로 실제 기기의 OS 패치 상태를 확정할 수 없습니다. 검증 범위와 한계는 [OWASP 대응 범위](https://github.com/ictechgy/apsa/blob/main/docs/OWASP_COVERAGE.md)와 [지원 표](https://github.com/ictechgy/apsa/blob/main/docs/SUPPORTED_MATRIX.md)를 참고하세요.

## 설치와 첫 실행

**macOS 또는 Linux**에서 **uv**를 설치합니다. APSA의 지원 대상은 **CPython 3.11과 3.12**이며, 모든 호스트·Python 조합을 테스트한 것은 아닙니다([지원 표](https://github.com/ictechgy/apsa/blob/main/docs/SUPPORTED_MATRIX.md) 참고). 예제는 Python 3.12를 선택하고 필요하면 uv가 내려받습니다. 최초 설치는 네트워크를 사용할 수 있으며, 이후 검사는 로컬 입력과 캐시를 사용할 수 있습니다.

[PyPI](https://pypi.org/project/apsa/)에서 배포 패키지를 설치합니다.

```sh
uv tool install --python 3.12 apsa==1.1.0
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
| `apsa scan TARGET --online` | 발견한 의존성 이름·버전을 OSV에 전송 |
| `apsa intel watch --online` | 저장된 의존성 이름·버전도 OSV에 전송 |

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

읽을 수 없는 소스 폴더와 파일은 경고와 불완전한 coverage로 남습니다. 지원하는 파일을 하나도 읽을 수 없는 소스 트리는 명시적인 실행 오류가 됩니다. 저장소 캡처 실패는 `not-run`으로 남으며 canary가 삭제됐다는 근거가 될 수 없습니다.

| 종료 코드 | 통합 CLI에서의 의미 |
| --- | --- |
| `0` | 명령 완료 또는 정책 통과 |
| `1` | 실행 오류 |
| `2` | 잘못된 인자 |
| `3` | 불완전한 감사·정책, 보고서 검증 실패, 취약점 정보 동기화 실패(부분 실패 포함) |
| `4` | 발견 항목이 설정한 CI 임계값 초과 |
| `130` | 중단 |

`--json`은 `ok`, `data` 또는 `error`, `exit_code`를 담은 envelope를 출력합니다. Watch는 주기마다 JSON envelope 하나를 출력합니다(NDJSON). `ok`는 코드 `0`과 `4`에서 `true`입니다. 코드 `4`는 평가 자체는 성공했지만 CI 임계값을 초과했다는 뜻입니다. CI는 `exit_code`와 정책 결과를 확인해야 합니다. 코드 `3`과 `4`에서도 보고서가 생성될 수 있습니다. 정책·백업·제한·문제 해결은 [CI 예제](https://github.com/ictechgy/apsa/blob/main/docs/ci-example.yml)와 [운영 가이드](https://github.com/ictechgy/apsa/blob/main/docs/OPERATIONS.md)를 참고하세요.

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

MCP는 stdio를 사용하며 명시적인 `--root`가 필요합니다. 여러 root는 옵션을 반복해서 지정합니다. `integrations`에 root를 주지 않으면 현재 폴더를 사용합니다. Root는 검사 대상과 해당 보고서·작업 접근을 제한합니다. `--allow-any-root`는 이 제한을 명시적으로 해제합니다. APSA는 모델 클라이언트 설정을 자동 변경하지 않으며, 클라이언트 인증은 클라이언트가 관리합니다.

| 목적 | MCP 도구 |
| --- | --- |
| 감사 | `capabilities`, `audit_scan`, `audit_start`, `audit_reassess` |
| 작업 | `jobs_list`, `jobs_status`, `jobs_cancel` |
| 보고서 | `reports_list`, `reports_get`, `reports_compare`, `reports_export_baseline` |
| 취약점 정보 | `intelligence_sync`, `intelligence_search`, `intelligence_get`, `dependency_check` |
| 정책 | `policy_evaluate` |
| 런타임 계획 | `runtime_plan`, `runtime_devices` |

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

소스는 [GitHub](https://github.com/ictechgy/apsa)에 공개되어 있습니다. [LICENSE](https://github.com/ictechgy/apsa/blob/main/LICENSE)는 원래 Quaygate의 MIT 고지를 보존합니다. 이번 공개는 통합 제품에 추가 라이선스를 선언하지 않습니다.

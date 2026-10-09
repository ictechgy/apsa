# GitHub 공개 소스 — 2026-10-06

## Published 1.2.0 — 2026-10-09

[1.2.0](https://github.com/ictechgy/apsa/releases/tag/v1.2.0) is bound to source commit `8d915753a930279c7816f0f99e4e843505df92a6` through a lightweight tag that was not moved. Public `main` was fast-forwarded to the same commit; that push skipped the main-context publish path as intended. The tag-context [release workflow 37906807519](https://github.com/ictechgy/apsa/actions/runs/37906807519) passed all nine CI jobs (Linux/macOS × Python 3.11/3.12, required-mode Linux/macOS parser isolation, Homebrew framework Python, nested Seatbelt and Ubuntu 24.04 bubblewrap compatibility), the verified package build, PyPI Trusted Publishing and the GitHub release downloads. PyPI lists `apsa-1.2.0-py3-none-any.whl` and `apsa-1.2.0.tar.gz`; a fresh `uv pip install apsa==1.2.0` reported version 1.2.0 and rule version `2026.10.09.apsa.120` on a synthetic source scan. The release-candidate snapshot passed CI run [37906348625](https://github.com/ictechgy/apsa/actions/runs/37906348625) with 883 distinct tests. Independent code review approved the release delta `cbf3c44..8d91575`; the architecture review returned WATCH without blockers after its earlier BLOCK on sandbox activation was resolved. Deferred non-blocking items: pinning the Homebrew interpreter and wheel build backend in the compatibility job, freezing released skill fixtures by hash, and tolerating a broken optional parent package during probe module discovery.

## APSA 1.2.0 analysis extension — candidate, 2026-10-09

1.2.0 packages the bounded analysis extension developed on `hardening/real-app-cve-v1`: AAB base-manifest/module DEX analysis, embedded IPA Mach-O metadata, narrow Objective-C `.m` candidates, descriptor-safe parser input staging and macOS/Linux parser OS isolation that is on by default where an activation probe succeeds. Scope and limits are in [NEXT_ANALYSIS.md](docs/NEXT_ANALYSIS.md); measurements are in [NEXT_RESULTS.md](benchmarks/NEXT_RESULTS.md). Every AAB audit stays partial, embedded IPA metadata does not authenticate signatures, Objective-C findings remain candidates, and the parser sandbox does not isolate the parent CLI or MCP client.

The evaluated runtime is public `9c2d5d5033132ee2113a2638e17d3225d2e7dbc8` (runtime tree `133b48e59bbf01bb2aad8458812020eee6ae157f`), whose [CI 37899396137](https://github.com/ictechgy/apsa/actions/runs/37899396137) passed all six jobs with 873 distinct tests. Its code review approved and its architecture review cleared that snapshot; documentation closure followed at public `cbf3c449358f3aedaff87ce6da3a04ad0fea00f3`. The 1.2.0 release delta on top of that tree adds package/rule version metadata (`1.2.0`, `2026.10.09.apsa.120`); registration of the 1.1.0 default skill hashes so unmodified 1.1.0 skills upgrade without `--force` while user edits stay protected; an input-free parser sandbox activation probe so that `auto` records `unavailable` instead of aborting when a present backend cannot start (nested Seatbelt, blocked user namespaces), while `required` refuses with an explicit reason; the exact macOS framework-Python app-bundle interpreter in the Seatbelt exec allowance; sandbox-specific failure messages; lock-safe audit database permission repair, fixing a pre-existing race in which opening a second store in one process released the live connection's SQLite WAL-index locks and could crash it with SIGBUS when another process reinitialized the shared memory (observed once in macOS/Python 3.11 CI); a hosted isolation compatibility job (Homebrew framework Python, nested Seatbelt, Ubuntu 24.04 bubblewrap); regression tests; and release documentation. The holdout and replay measurements were not rerun after this delta. The release delta requires its own targeted review and the supported CI matrix; earlier approvals do not extend to it automatically.

Evaluation numbers keep their recorded meaning. The independent holdout agrees on 4 / 4 selected declaration facts and 16 / 16 selected Apple CVE boundary decisions, not 16 vulnerabilities or device patch verification. The frozen replay keeps 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions on the original dependency units and two unresolved catalog-usage abstentions on selected app paths. Publication is confirmed only by the tag-context release workflow, PyPI and the GitHub release downloads, recorded below once complete.

## Published 1.0.6 and 1.1.0 — 2026-10-08

The requested release sequence is complete through 1.1.0. [1.0.6](https://github.com/ictechgy/apsa/releases/tag/v1.0.6) is bound to source commit `2fbca30bfc03c8e5ef2b8dd0d16dd1ae720fc361`; [1.1.0](https://github.com/ictechgy/apsa/releases/tag/v1.1.0) is bound to `a2149c23288079e4e4dd57c7eda1bd822c9097d1`, whose tree exactly matches the independently reviewed local candidate. The tags were not moved. The successful tag-context workflows are [1.0.6](https://github.com/ictechgy/apsa/actions/runs/37794658338) and [1.1.0](https://github.com/ictechgy/apsa/actions/runs/37796258526). Each passed the four supported CI environments, verified package build, PyPI upload and release downloads. Local 1.1 validation also covered 648 pytest tests, Ruff/format/Pyright, corpus 31/31, repeated package hashes, clean offline installation and new-feature CLI/MCP smoke.

Main-context publish attempts failed before publisher steps after the approved tags were created; their exact cause was not confirmed. User-authorized, independently reviewed recovery workflows dispatched only the fixed version/commit pair and were removed after use. Tag creation and source upload were not treated as package publication. One separately triggered macOS/Python 3.11 CI job failed on its first execution and passed on one operational retry; the release matrix and the final recovery source CI passed all four environments. No test or coverage gate was disabled.

Code review approved the 1.1 snapshot; the architectural verdict is WATCH without source blockers. The documented tradeoffs remain numeric cursors scoped to report/section/filters, unsigned baseline approval with an externally pinned artifact hash, and declared source selection without Gradle/Xcode merging. These limits are not new analysis capabilities. AAB, IPA embedded binaries, Objective-C and parser OS sandbox remain later stages in [ROADMAP.md](docs/ROADMAP.md).

The candidate and older entries below are historical validation notes. Registry publication is established by the linked release workflow and downloads, not by a local build manifest's `published` field.

공개 저장소: [ictechgy/apsa](https://github.com/ictechgy/apsa). 영문 README가 원본이며 한국어 README를 함께 제공합니다. 현재 공개 소스의 검증은 [GitHub Actions](https://github.com/ictechgy/apsa/actions)에서 확인할 수 있습니다.

태그 배포 경로는 [PyPI](https://pypi.org/project/apsa/)와 [GitHub Releases](https://github.com/ictechgy/apsa/releases)입니다. `release.yml`은 `pypi` 환경의 Trusted Publisher를 사용하며, 태그·패키지 버전 일치, 지원 대상 CI 네 조합, 업로드할 패키지의 반복 빌드와 새 환경 설치 검증이 통과해야 업로드합니다. 다운로드와 체크섬 구성은 [배포 안내](docs/PUBLISHING.md)에 기록합니다. 이 배포 설정 변경은 새 보안 검토 승인을 의미하지 않습니다.

아래는 로컬 개발 과정의 검증 이력입니다. 원본 감사 데이터, 검토 로그, 개인 설정, 스크린샷, 로컬 가상 환경과 배포 폴더는 공개 저장소에 포함하지 않습니다. 아래의 내부 증거 경로와 과거 배포 경로는 로컬 기록을 가리키며 공개 다운로드를 뜻하지 않습니다. 과거 외부 리뷰를 현재 공개 스냅샷에 대한 새 보안 승인으로 취급하지 않습니다. 로컬 배포 파일은 `make release`로 새 출력 폴더에 생성할 수 있습니다.

---

# APSA 1.0.6 evidence correctness

Mixed unsupported source languages and per-file pattern truncation are incomplete. OS-CVE records explicitly report bounded recent-window correlation, without a historical-completeness claim. Dependency declarations produce candidates; exact inventory produces version-affected evidence. MCP fallback uses isolated Python startup. The adoption recipe uses unified scan, a reviewed project policy, current dependencies and exit codes. New regression checks use generated synthetic fixtures outside runtime data paths. Release validation and independent review are recorded for the final snapshot; older approvals do not apply.

# APSA 1.1 model and team workflows — candidate

Bounded section/evidence pages preserve response omissions separately from audit completeness. Portable baselines require explicit approval provenance and an externally pinned byte hash; source selection is part of baseline identity. Policy decision exports preserve the normalized policy, report/policy hashes, baseline provenance and waiver decisions. Explicit module/configuration selection is shared by foreground and persistent audits without build-system variant merging. Packaged skills and both READMEs describe the contract; default 1.0.6 skill upgrades preserve user customizations.

Local source validation: **648 pytest tests passed**, Ruff check/format passed, Pyright reported no errors, and the handcrafted corpus matched **31/31** cases. These are regression checks with synthetic inputs. The supported CI matrix, clean-release package checks, independent final-snapshot review and registry publication are separate gates. This entry records a candidate, not a completed publication. The requested release order remains 1.0.6, then 1.1, then the stages in [ROADMAP.md](docs/ROADMAP.md).

---

# APSA (앱사) 1.0.5 검사 누락 수정 — 2026-10-08

읽을 수 없는 소스 하위 디렉터리를 조용히 건너뛰던 열거 오류를 경고·partial·불완전한 fingerprint로 표시합니다. 열거한 파일의 상태 확인이나 읽기 실패도 같은 불완전 경로로 처리합니다. 지원하는 파일을 하나도 읽을 수 없으면 명시적인 실행 오류가 됩니다. 의도적인 제외 폴더와 심볼릭 링크 정책은 유지합니다.

iOS 로컬 저장소 캡처는 디렉터리 열거·파일 확인·읽기 실패를 `not-run`으로 남겨 canary 삭제 검사가 통과하지 않도록 합니다. 캡처 오류에 포함된 canary도 label로 가리고, 불완전한 재관찰 때문에 기존 런타임 발견 근거를 지우지 않습니다.

로컬 `make test benchmark`: **612개 pytest 통과**, Ruff check/format 통과, Pyright 오류 0건, 기존 수작업 corpus **31/31 일치**. 추가 22개 회귀 사례는 권한 거부·중첩 폴더·파일 상태 오류·CI 종료 코드·기존 런타임 근거 보존·canary 가림과 정상 삭제·의도적 제외 대조군을 검증합니다. 앞쪽 파일의 읽기 실패 이후에도 읽을 수 있는 다른 파일을 검사하며, 디렉터리에 실행 권한이 없어 자식의 상태 확인이 실패하는 경우도 검증합니다. 저장소 확인은 로컬 어댑터를 이용하며 새 시뮬레이터·실기기 실행이나 운영 앱 탐지율 측정은 포함하지 않습니다.

이 로컬 결과는 최종 스냅샷의 독립 리뷰 또는 업로드 완료를 뜻하지 않습니다. 업로드 전에 독립 리뷰, 지원 대상 CI 네 조합, 반복 wheel/sdist 빌드와 깨끗한 설치 검증을 거칩니다. 배포 완료 시 다운로드와 manifest는 [1.0.5 릴리스](https://github.com/ictechgy/apsa/releases/tag/v1.0.5)에서 확인할 수 있습니다.

---

# APSA (앱사) 1.0.4 리뷰 수정 — 2026-10-06

작업 프로세스의 Python import 경로, 승인된 MCP sidecar·정책·시나리오·소스 경로의 재해석, 소스 열거 제한의 부분 검사 표시, SQLite DB/WAL/SHM 생성 권한을 보완합니다. 잘못된 KEV routing 필드는 기존 캐시를 보존하며 오류를 표시하고, 프로젝트별 인텔 유효 시간과 CVE의 component·patch·snapshot 분기를 advisory와 version-affected 발견 근거에 모두 보존합니다. CLI의 초기 부모 심볼릭 링크 처리와 기존 명령·데이터·발견 ID는 유지합니다.

로컬 격리 사본에서 `make test benchmark`: **590개 pytest 통과**, Ruff check/format 통과, Pyright 오류 0건, 기존 수작업 corpus **31/31 일치**. 46개 회귀 사례는 두 worker의 cwd/PYTHONPATH 입력, 승인 후 경로 교체, 동결된 런타임 시나리오, 열거 제한, 공유 home의 DB 권한, malformed KEV, custom freshness, 분기 출처와 1.0.3 스킬 갱신을 검증합니다. 새 실기기 실행이나 상용 앱 탐지율 검증은 포함하지 않습니다.

이 로컬 검사 결과는 독립 리뷰 또는 배포 완료를 뜻하지 않습니다. 최종 태그 스냅샷의 리뷰 기록은 별도로 바인딩하며, 업로드 전 CI 네 환경과 반복 패키지 빌드·깨끗한 설치 검증을 거칩니다. 실제 배포 완료·다운로드와 manifest는 [1.0.4 릴리스](https://github.com/ictechgy/apsa/releases/tag/v1.0.4)에서 확인하십시오.

---

# APSA (앱사) 1.0.3 리네이밍 — 2026-10-06

제품 표기, `apsa` CLI·배포 패키지·Python 진입점·MCP URI·스킬을 새 이름으로 통일합니다. 기존 명령어·URI·환경 변수·감사 DB는 호환하며 이전 발견 ID와 lint provenance를 보존합니다. 과거 독립 보안 리뷰는 당시 스냅샷에만 적용됩니다. 현재 변경의 검증과 설치 근거는 `.omx/renames/` 아래에 별도로 기록합니다.

검증: **544개 테스트 통과**, Ruff 검사·포맷 통과, Pyright 오류 0건, 세 스킬 frontmatter 검증 통과. `apsa`와 기존 Python 진입점의 MCP stdio 왕복 및 세 URI의 동일 보고서 응답, 구버전 기본 스킬 갱신과 사용자 수정본 보존을 확인했습니다. 검사 규칙과 감사 DB schema는 변경하지 않습니다.

현재 배포 폴더는 `dist/apsa-1.0.3`입니다. 반복 빌드·새 환경의 소스/APK 검사·MCP·세 CLI 별칭/모듈/스킬 검증 근거는 이 폴더의 `release-manifest.json`과 `SHA256SUMS`로 기록합니다. 아래는 이전 이름·버전의 검증 이력입니다.

---

# Quaygate (키게이트) 1.0.2 제품 리뷰 수정 — 2026-10-06

현재 변경은 부분 검사 종료 코드, iOS 메인·내장 식별자와 ZIP 경로 구조, 메인 설정 우선 읽기와 용량 한도, 빌드별 플랫폼 식별, ARSC·Mach-O·ELF·인증서 경계, CVE 수집/처리 상태, OSV 심각도, 감시의 명시적 온라인 조회와 이력 중복 방지, MCP 기본 경로 제한, 패키지 스킬 설치, 비교·runtime·sidecar 경계를 보완합니다.

검증: 기존 478개와 새 회귀 61개를 합친 539개 테스트, Ruff 검사·포맷, Pyright 오류 0건. 새 실기기·대형 상용 앱의 탐지율 검증은 포함하지 않습니다. 원본 외부 리뷰와 수정 후 독립 리뷰는 `.omx/reviews/20261005T161101Z/`의 불변 스냅샷·패킷·실행 기록에 바인딩합니다. 검증 통과를 독립 승인으로 간주하지 않으며, 최종 판정은 별도 REVIEW 문서에 기록합니다.

반복 wheel/sdist 빌드와 새 환경 설치·소스/APK·MCP·휠 스킬 설치 결과는 `dist/quaygate-1.0.2-product-final/release-manifest.json` 및 `SHA256SUMS`로 확인합니다. 이전 배포 폴더와 검토 중 생성한 후보 산출물을 덮어쓰지 않습니다.

## 이전 버전 이력

# Quaygate (키게이트) 1.0.1 표기 정리 — 2026-10-06

사용자가 승인한 표기는 영문 **Quaygate**, 한글 **키게이트**, 발음 **key-gate**입니다. README·브랜드 규칙·제품/디자인 문서, CLI 도움말과 사람용 결과 제목, TUI 제목, Markdown 보고서, MCP 안내와 두 스킬에 반영했습니다. CLI·패키지·MCP 식별자와 감사 데이터 저장 위치는 `quaygate` 통합 제품의 기존 계약을 따릅니다.

이번 변경의 검증: **478개 테스트 통과**, Ruff 검사·포맷 통과, Pyright 오류 0건, 두 스킬의 frontmatter 검증 통과. 새 검사 규칙이나 취약점 탐지 기능은 추가하지 않았으며, 이전 보안 리뷰를 새 승인으로 표시하지 않습니다.

1.0.1 배포 입력과 새 환경 설치·오프라인 소스/APK·MCP 검증, 반복 빌드 일치 여부는 `dist/quaygate-1.0.1/release-manifest.json`과 `SHA256SUMS`에 기록합니다. 1.0.0 산출물과 아래 검증 기록은 이전 통합 버전의 이력입니다.

## Quaygate 1.0.0 통합 검증 이력

이 파일은 새 통합 제품의 검증만 기록합니다. 이전 Mobile Audit과 Quaygate의 실기기 실행·독립 리뷰 결과는 `docs/legacy/`의 이력이며, 통합 변경에 대한 새 독립 승인으로 간주하지 않습니다.

통합 패키지는 소스 분석과 취약점 대조, 두 APK/IPA 정적 엔진, TUI·CLI·MCP, 공통 이력·CI 정책·지속 작업을 포함합니다. 형제 저장소에 실행 시 의존하지 않습니다. 기존 Mobile Audit 저장소와 staged 파일은 보존합니다. 기존 데이터는 동일한 저장 위치와 schema에서 읽습니다.

검증 결과: 기존 466개와 통합 검증 12개를 합친 **478개 테스트 통과**, Ruff 검사·포맷과 Pyright 오류 0건, 기존 범위의 수작업 corpus **31/31 일치**입니다. corpus는 Quaygate의 모든 규칙이나 실제 앱 탐지율을 대표하지 않습니다. 실제 SDK 컴파일 DEX/APK fixture와 생성 Mach-O/IPA를 사용하며, MCP stdio와 persistent job을 통해 두 엔진의 근거가 같은 보고서에 저장되는지 확인합니다. 테스트는 통합된 CLI/TUI/MCP·지속 작업, 입력 경계와 정책·보고서 무결성 회귀를 검증합니다.

배포 패키지의 반복 빌드·새 환경 검사 결과와 파일 해시는 `dist/quaygate-1.0.0/release-manifest.json` 및 `SHA256SUMS`에서 확인합니다. 이 manifest가 생성되려면 두 빌드의 wheel/sdist가 일치하고, 새 환경에서 소스·두 APK 엔진·MCP stdio 검사가 통과해야 합니다.

이 통합 작업에서는 새 실기기 시나리오나 모델별 클라이언트 설정을 실행하지 않았습니다. 공개 피드의 수집·재평가 기능은 기존 엔진을 그대로 통합했고, 이번 기능 변경 검증은 캐시/fixture 기반입니다. 외부 배포·업로드는 하지 않습니다.

# APSA (앱사) 통합 설계

`apsa` 패키지 하나가 `quaygate` 정적 린트 모듈과 `mobile_audit` 감사 모듈을 함께 설치합니다. 유지보수 대상 저장소는 이 폴더입니다. 원래 Mobile Audit 폴더와 그 staged 변경은 보존하며, 실행 시 형제 폴더·절대 소스 경로에 의존하지 않습니다.

`scan` → 공통 감사 엔진 → 자원 제한 parser worker → 고정 입력 사본 → Mobile Audit 분석 + Quaygate 린트 adapter → 공통 findings/coverage → 동일한 Store/정책/출력. TUI와 MCP, 지속 작업도 이 경로를 사용합니다. 기존 `apk/ipa/device`는 호환 린트 경로입니다.

두 바이너리 엔진의 입력 해시는 동일해야 합니다. parser worker의 CPU·RSS·시간·출력·동시 실행 한도와 안전한 파일 열기·archive 검증을 공유합니다. 기존 `openssl` 인증서 보조 프로세스도 parser 프로세스 트리 자원 감시 안에서 실행됩니다. 자원 제한과 별도로 1.2.0은 파서 프로세스의 선택적 OS 권한 격리를 제공합니다. 가용성·적용 상태·실패 동작은 [분석 범위](NEXT_ANALYSIS.md)를 참고하세요. 읽는 앱은 사용자 소유 또는 승인을 받은 대상으로 한정합니다.

adapter는 린트의 warn/fail을 그대로 confirmed 취약점으로 바꾸지 않습니다. 문자열·카나리·서명 방식·provisioning은 candidate입니다. 정확히 동일한 루트 Manifest debuggable 사실은 기존 ID와 근거를 보존하고 출처·심각도를 합칩니다. 다른 분석 규칙은 출처별 ID를 유지합니다. 서로 다른 의미의 ATS·DEX 규칙을 이름 유사성만으로 병합하지 않습니다.

검사 예외는 타입만 경고에 기록하고 해당 검사 coverage를 partial로 표시합니다. 다른 엔진의 증거는 보존됩니다. 미확인 profile, 암호화/빈 실행 파일, 없는 DEX는 검사 통과가 아닙니다. 필수 coverage와 partial 정책은 CI에서 incomplete입니다. 새 정적 규칙을 적용하려면 scan을 다시 실행해야 하며, reassess는 이전 인벤토리를 그대로 사용합니다.

MCP의 root 제한, 과거 canonical 대상 권한 확인, runtime opt-in, 메타데이터만 전달하는 context를 유지합니다. 새 `apsa://` resource와 기존 `quaygate://`·`mobile-audit://` resource가 같은 권한 검사를 거칩니다. 모델용 서버 이름과 스킬 경로는 APSA를 사용합니다.

소스는 GitHub의 `ictechgy/apsa` 공개 저장소에서 제공합니다. 루트 LICENSE는 원래 Quaygate 코드의 MIT 고지이며 이번 공개로 통합 코드에 추가 라이선스를 선언하지 않습니다. 기존 빌드 산출물·샘플 다운로드·개인 감사 데이터·가상 환경을 패키지에 넣지 않습니다.

MCP는 `--root PATH`를 요구하며 경로 제한 해제는 `--allow-any-root`로 명시합니다. `integrations`는 현재 디렉터리를 기본 허용 경로로 생성하고 스킬의 실제 설치 여부를 표시합니다. 휠에 세 스킬을 포함하며 `skill install --name apsa|quaygate|mobile-audit`로 설치할 수 있습니다. 사용자 수정본은 `--force` 없이는 덮어쓰지 않습니다.

foreground scan, 정책, TUI·MCP 보고서 요약과 작업 상태는 같은 명시적 partial 판정 기준을 사용합니다. optional not-run은 계속 표시하며 필수 규칙은 정책으로 선택합니다. OSV 조회를 요청했는데 전송·파싱·예산 문제 또는 미해결/미지원 의존성 때문에 대조할 수 없으면 부분 결과로 처리합니다. 미지원 의존성도 요청한 검사 범위이므로 자동 통과시키지 않습니다.

1.1의 모델 context는 제한된 section 페이지이며 `partial_response`와 `audit_incomplete`를 분리합니다. `latest` 조회 후 반환된 불변 보고서 ID를 유지하고 다음 cursor로 진행합니다. 휴대형 기준선은 승인 메타데이터·보고서 내부 해시·외부에서 고정한 artifact 해시를 확인하며, 다른 앱이나 소스 module/configuration에는 재사용하지 않습니다. `scan --policy --out`은 보고서와 별도 판정 파일을 저장합니다. 소스 설정 선택은 선언 파일 하나를 고르는 기능이며 Gradle/Xcode 빌드 설정을 병합하지 않습니다. 영문 계약과 예제는 [MODEL_WORKFLOWS.md](MODEL_WORKFLOWS.md)를 따릅니다.

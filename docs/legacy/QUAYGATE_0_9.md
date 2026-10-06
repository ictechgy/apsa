# quaygate

**모바일 앱 정적 보안 점검 CLI** — APK/IPA를 의존성 없는 순수 파이썬(표준 라이브러리만)으로
검사하는 린트급 게이트. 무거운 프레임워크 없이 CI에서 `python3` 한 번에 돌린다.
심층 분석(동적 계측·난독 해제)은 MobSF/Frida 영역 — 이 도구는 빠른 정적 스크리닝에 집중한다.
보조 모드로 Android **본인 기기** 자가 점검(`device`)도 제공한다.

이름: 앱(선박)이 배포(입항) 전 지나는 부두 검문소(quay gate) — 명명 심사는 [NAMING.md](NAMING.md).

> **서브프로세스 고지** APK 서명 인증서 분석은 PATH의 `openssl`을 실행합니다(없으면 해당
> 항목만 '확인불가'로 표시). 보안 민감 환경에서는 PATH 무결성을 확인하세요.

> **실측 샘플** 검증 상태의 실측은 공개 저장소(F-Droid·GitHub Releases) 배포본 기준이다.

> **사용 범위** 본인이 개발했거나 명시적 승인을 받은 앱·기기만 점검하세요.
> 타인 앱의 취약점을 무단 탐색·공격에 활용하는 것은 불법이다.
> 이 도구는 읽기 전용이며 파일·네트워크 어느 쪽도 수정하지 않는다.

## 사용법

```sh
cd quaygate
python3 -m quaygate apk app.apk            # APK 정적 점검
python3 -m quaygate ipa app.ipa            # IPA 정적 점검
python3 -m quaygate apk app.apk --json     # JSON
python3 -m quaygate apk app.apk --sarif    # SARIF 2.1.0 (code scanning 업로드용)
python3 -m quaygate device                 # 연결된 Android 기기 자가 점검(adb)
```

종료 코드: `0` 경고 이하만 · `1` 심각(fail) 있음 · `2` 파일·adb 오류.
CI 레시피: [docs/ci-example.yml](docs/ci-example.yml).

## 설치

의존성이 없다(순수 표준 라이브러리, Python 3.9+). 배포 후에는 `pip install quaygate`
— 배포 전에는 저장소에서 바로:

```sh
python3 -m quaygate apk app.apk        # 저장소 루트에서
scripts/release-check.sh app.apk       # 릴리즈 전 체크(테스트·패키지 빌드·스모크)
```

## 점검 항목

### 앱 — APK (매니페스트·networkSecurityConfig·서명·인증서·DEX)

| ID | 항목 | 판정 |
|---|---|---|
| app-debuggable | 디버그 모드 | true → 심각 |
| app-allowbackup | ADB/클라우드 백업 | true·선언 없음(기본 true) → 경고 |
| app-cleartext | 평문 트래픽 | networkSecurityConfig(해석 가능 시 우선)·usesCleartextTraffic·targetSdk 기준 판정 |
| app-nsc-user-trust | 사용자 인증서 신뢰 | trust-anchors src=user → 경고 |
| app-nsc-debug-overrides | debug-overrides 잔존 | 정의 존재 → 경고 |
| app-exported | 외부 공개 컴포넌트(도달성 분류) | 보호 없는 exported=true → 경고 · 타 앱 도달 가능(암시적·참조 해석 실패 포함) → 정보 · 런처·보호 브로드캐스트(명시 포함)는 정상 공개로 통과 |
| app-deeplink | 딥링크 도달 표면 | 커스텀 스킴 BROWSABLE → 경고(스킴 가로채기) · autoVerify 없는 http(s) → 낮음 · 검증됨 → 통과 |
| app-provider-grant | exported provider URI 권한 위임 | 속성 또는 grant-uri-permissions 요소 → 경고 |
| app-provider-paths | provider 경로 권한 | 권한 없는 path-permission(프레임워크 무시) → 정보 · 경로 패턴만 보호 → 정보 |
| app-permissions-dangerous | 민감 권한 | 목록 정보 |
| app-custom-permissions | 커스텀 권한 보호 수준 | normal/dangerous → 정보 |
| app-target-sdk | targetSdk | <23 심각 · <29 보통 · <30 낮음 |
| app-signature | 서명 방식 | 없음 심각 · v1만 경고 · v2+ 통과 |
| app-cert | 서명 인증서(v1 한정) | 디버그 키 심각 · 만료 낮음 · v2/v3 전용은 확인불가 (openssl 있을 때) |
| dex-weak-crypto / dex-webview | 약한 암호·WebView **호출 지점**(바이트코드 분석) | invoke 명령+const-string 추적으로 클래스·메서드·인자까지 판정 |
| dex-dynamic-code | 동적 코드·리플렉션 호출 지점 | DexClassLoader/Runtime.exec/System.load/Method.invoke — 정보 |
| dex-secrets / dex-cleartext-urls / dex-trackers | DEX 문자열 지표 | 서버 측 시크릿 심각, 나머지 경고·정보(휴리스틱) · 전체 읽기 실패 시 확인불가 |
| dex-embedded-keys | 앱 내장 공개 키 | Maps/Firebase 등 AIza 패턴 → 경고(제한 확인 권고) |
| native-hardening | 네이티브 .so 하드닝(checksec) | 실행 스택 경고·미적용 항목 낮음 — PIE/RELRO/NX/카나리 |

networkSecurityConfig는 세 형태를 해석한다: `@xml/이름` 문자열 참조, `@<숫자>` 리소스 ID
참조(내장 resources.arsc 최소 파서로 이름 복원 — aapt2 sparse 인코딩 대응), 그리고
경로 난독화 APK(`res/xY.xml` 해시명 — 리소스 값 문자열에 든 실제 경로 사용).
상속 규칙 전체가 아니라 명시적 선언만 보고한다.

### 앱 — IPA (Info.plist·바이너리)

| ID | 항목 | 판정 |
|---|---|---|
| ipa-ats | ATS 전역 해제 | NSAllowsArbitraryLoads → 경고 |
| ipa-file-sharing | iTunes 파일 공유 | UIFileSharingEnabled → 정보 |
| ipa-url-schemes | 커스텀 URL 스킴 | 목록 정보 |
| ipa-min-os | 최소 지원 OS | <15 → 경고 |
| ipa-binary-hardening | Mach-O 하드닝 | PIE 없음 경고·카나리 미탐지 낮음 |
| bin-* | 바이너리 문자열 지표 | dex-*와 동일 스캐너. FairPlay 암호화(cryptid) 감지 시 확인불가 |

### 기기 — Android (보조 모드, adb 읽기 전용)

보안 패치 수준·암호화·SELinux·잠금 화면(스와이프 잠금과 무잠금 구분은 불가 — 확인 필요)·부트로더·디버깅 설정·설치 검증·백업·설치 앱 플래그 등
16종. 요구사항: adb, USB 디버깅. 자세한 목록은 [PLAN.md](PLAN.md).

`dex-*`/`bin-*`는 문자열 스캔 휴리스틱이다 — 패턴 일치는 실제 취약 사용을 보증하지 않고
리포트에 항상 "지표"로 표기된다.

## 검증 상태

- 단위 테스트 207건(AXML/DEX/Mach-O/arsc/ELF 파서부터 CLI·SARIF까지, 목업 바이너리 생성 방식):
  `python3 -m unittest discover -s tests`
- **실측 1 — APK**: F-Droid 2.0.1(org.fdroid.fdroid, targetSdk 37): 패키지·컴포넌트·서명(v2+)·
  권한·DEX 지표·**서명 인증서(릴리스 키 정상 판정)** 확인(2026-10-04).
- **실측 2 — 도달성·딥링크**: F-Droid의 커스텀 스킴 딥링크 `market://`·`fdroidrepos://`
  2개 경고로 포착(실제 등록 스킴과 부합), 런처 진입점은 정상 암시적 exported로 분류(2026-10-04).
- **실측 5 — DEX 바이트코드·네이티브**: F-Droid APK에서 124,001개 메서드를 1.3초 스캔,
  약한 암호 호출 지점(zipsigner의 SHA1/MD5 등 15곳 — 실제 라이브러리와 부합)·WebView
  호출 미발견(FP 제거)·Method.invoke 108곳·libandroidx.graphics.path.so의 RELRO full
  판정. SideStore IPA는 PIE·스택 카나리 적용 통과(2026-10-04).
- **실측 6 — 디버그 인증서**: 실제 keytool+jarsigner로 서명한 APK에서
  `CN=Android Debug` 심각 판정 + v1-only 경고 정확 포착(2026-10-04).
- **실측 7 — 추가 실제 APK 3종(NewPipe·Termux·Markor)**: NewPipe의 커스텀 스킴
  `vnd.youtube://` 딥링크, Termux의 exported provider URI 권한 위임
  (TermuxDocumentsProvider)·`libtermux-bootstrap.so` RELRO partial·카나리 미적용 포착.
  bool 값 리소스 해석 실측(F-Droid 635·NewPipe 1,097개 — @bool 참조 속성 해석).
  113MB APK(Termux)도 0.4초 처리(2026-10-04).
- **배포 준비**: wheel+sdist 빌드·venv 설치·콘솔 스크립트(`quaygate`) 실행 검증 완료,
  PyPI 이름 `quaygate` 미등록 확인(404), `scripts/release-check.sh` 전 단계 통과.
- **외부 정밀 리뷰 반영 3차(2026-10-05, v0.9.4 — REVIEW_2026-10-06-rev2)**: SARIF 경고
  가시성 복구(warn→level warning) · BadZipFile 크래시 수정(부분 실패 처리) · 리포트 로그
  위조 차단(살균) · .so 전 ABI 검사 · 참조형 속성 해석 통일(NSC·provider·debug-overrides) ·
  FAT64 Mach-O · ATS 도메인 예외 · get-task-allow 개발 서명 감지. 테스트 207건.
- **외부 정밀 리뷰 반영(2026-10-05, v0.9.2)**: 4-레인 검증 리뷰(REVIEW_2026-10-04.md,
  aapt2·dexdump·NDK·Xcode 실측 포함)의 P2 22건 중 17건 수정 — CI 게이트 종료 코드 보존,
  예외 랩핑/NameError 제거, arsc 플래그 +9·compact·OFFSET16 실제 형식, DEX cmp 크기표,
  @bool 참조 해석, protectionLevel 숫자, 런처 노이즈 제거, provider 읽기/쓰기 권한,
  NSC/DEX/IPA fail-open 정리(0스캔·해석 실패 → 확인불가), AIza 등급 분리, IPA 스트리밍
  스캔, SARIF kind/level 규격. 남은 항목은 PLAN.md 참조.
- **실측 3 — networkSecurityConfig 엔드투엔드**: F-Droid의 리소스 ID 참조(`@2132017162`)를
  2MB resources.arsc(4,834 엔트리)에서 복원, 경로 난독화(`res/xY.xml`)를 값 문자열로 우회해
  실제 정책 파일 파싱 — base 평문 허용, 도메인 예외 `onion`(Tor 미러), 사용자 인증서 신뢰
  모두 실제 F-Droid 설계와 부합(2026-10-04).
- **실측 4 — IPA**: SideStore 0.7.0-alpha(com.SideStore.SideStore, minOS 15.0): Info.plist(ATS
  전역 해제·파일 공유·URL 스킴)·Mach-O cryptid(평문)·바이너리 지표·**SARIF 출력**(5 규칙·5 결과) 확인(2026-10-04).
- 미실측: FairPlay 암호화 IPA(App Store 계정 필요 — 배포 전 실측 불가)와 provider
  path-permission 무보호 경로는 목업만.
- 바이트코드 분석은 invoke+const-string 추적까지 — 레지스터 데이터플로·난독 해제 없음(문자열 인자
  귀속은 메서드 범위 휴리스틱). ELF/Mach-O 카나리는 심볼 문자열 탐지 휴리스틱.

## 로드맵

- 실제 배포 실행(twine upload — PyPI 계정 필요)과 저장소 공개는 사용자 결정 항목

설계·피벗 이력·명명: [PLAN.md](PLAN.md), [NAMING.md](NAMING.md).

# 추가 분석과 독립 정답 평가

[영어 원본](NEXT_RESULTS.md) · [구현·한계](../docs/NEXT_ANALYSIS.md) ·
[최초 독립 평가 JSON](results/2026-10-09-next-first-holdout.json) ·
[최초 개발 재평가 JSON](results/2026-10-09-next-first-replay.json) ·
[실행·리뷰 근거](results/2026-10-09-next-evidence.json).

이 결과는 배포 전 `2026.10.09.apsa.111-dev4` 개발 브랜치의 측정이며,
PyPI APSA 1.1.0의 결과가 아닙니다. 제한된 AAB protobuf·모듈 분석,
IPA 내장 Mach-O 메타데이터, Objective-C 후보, descriptor 기반 안전한
파서 입력 복사와 선택적 OS 격리를 추가했습니다. 앱 전체의 악용 가능성이나
일반적인 운영 정확도를 입증하지 않습니다.

## 독립 라벨을 사용한 최초 평가

독립 코드 리뷰 담당이 새 공개 저장소 두 개의 고정된 소스 사실과 버전 정답을
최초 APSA 검사 전에 작성했습니다. 고정된 [정답 파일](next_truth.json)의 SHA-256은
`b7d297d09997343049de79b79219c86d5c366c5673b2efc90d23ab9e25896bc7`입니다.
원본 앱·빌드 스크립트·백엔드·기기는 실행하지 않았습니다.

| 고정 소스 | 선택한 선언 사실 | 함수: 분석 / 건너뜀 / 본문 없음 | 원래 → 남은 구문 오류 파일 |
| --- | ---: | ---: | ---: |
| Tusky `43ae0bb4556392393a3d759ce42a93f3a003e83a` | catalog 이름·버전 2 / 2 | 2,456 / 0 / 297 | 1 → 0 |
| VLC iOS `2383783e8460538b79814f1131bd870fa2c0753b` | Podfile.lock 사실 2 / 2 | 5,165 / 275 / 17 | 22 → 22 |

Tusky의 선택한 `usesCleartextTraffic=false` 선언도 일치했습니다. catalog 선언은
실제 사용·포함 여부를 증명하지 않습니다. 두 앱의 감사와 인식한 함수 목록은 모두
불완전합니다. 앱별 세 번 검사에서 채점한 관찰값과 증거는 안정적이었습니다.

VLC 사전 검색은 Info.plist가 없다고 제안했지만, 검색으로 추정한 부재는 최초 검사
전에 임시 근거로 분류해 채점하지 않았습니다. 고정된 전체 소스에는 iOS·tvOS 앱,
테스트·확장 등의 Info.plist가 **8개** 있습니다. 부재 주장은 틀렸으며
`absence_label_verified: false`로 유지했습니다. 정답을 바꿔 통과시키지 않았습니다.

Apple CNA의 CVE-2025-31200·CVE-2025-31201·CVE-2025-43300 기록과 실제 수집한
공식 공지를 대조했습니다. 버전 경계 8개를 iOS·iPadOS 각각 검사해 선택한 판정
**16 / 16**이 일치했습니다. CVE 3개의 경계 사례이며 취약점 16개나 실기기 검사가
아닙니다.

| CVE | 영향 범위 쪽 버전 | 공식 수정 경계 | 공식 공지 |
| --- | --- | --- | --- |
| CVE-2025-31200 / CVE-2025-31201 | 18.4.0 | 18.4.1 | [Apple 122282](https://support.apple.com/en-us/122282) |
| CVE-2025-43300 | 18.6.1 | 18.6.2 | [Apple 124925](https://support.apple.com/en-us/124925) |
| CVE-2025-43300 | 16.7.11 | 16.7.12 | [Apple 125141](https://support.apple.com/en-us/125141) |

영향 범위는 `version-affected`, 수정 경계는 `outside-published-affected-range`입니다.
설치된 패치 검증·앱 도달 가능성은 미확인입니다. 미공개 제로데이, 공지 수집의
완전성, exploit 재현, 광범위한 경쟁 정확도는 채점하지 않았습니다.

[최초 평가 37896002099](https://github.com/ictechgy/apsa/actions/runs/37896002099)의
공개 커밋은 `3fb38a32f535f46b12befdce13bf6bf76317d326`, 트리는
`5cbc9e2b9a1813671a271e277b76810151a8b540`입니다. 보관한 최초 요약은 harness의
정규 형식과 바이트가 같으며 SHA-256은
`516ce3955c5d5702c3619c0a0f2e657041eeee13f256eba9858f7c6888616b03`입니다.
최초 `finding_statuses` 필드는 없는 `cve` 키를 선택했습니다. 공지 판정 채점은
별도이며 정상입니다. 개발 재실행에서는 실제 `OS-<CVE>` 규칙 ID를 사용하고,
최초 요약은 수정하지 않습니다.

artifact `11600073127`(`independent-next-holdout`)에는 공개 소스 ZIP·공지·검사
보고서가 있습니다. digest는
`sha256:c07f1f60a8d9f29a5352b8fd0b3caff271aaa3629fd87e6272275186b54ab4f9`,
만료는 `2026-11-08T06:54:48Z`입니다. 전체 오프라인 재현에는 만료 전에 입력을
보관해야 합니다. 최초 앱 검사는 OS 백엔드가 없어 `resource-limits-only`를
기록했습니다. 별도의 required OS 검사가 최초 검사의 보장을 바꾸지는 않습니다.

## 고정한 기존 앱 6개 개발 재평가

기존 공개 소스 6개·정답·OSV 응답은 그대로 재생합니다. 정답을 본 뒤 개발 검증한
결과입니다. 기존 의존성·CVE 사례 32개는 **TP 8, FP 0, FN 0, TN 19,
올바른 판정 보류 5개**를 유지했습니다.

선택한 실제 앱 CVE 경로는 **TP 1, TN 1, 판정 보류 2개**입니다. 기존 채점기는
판정 보류를 `failed`로 기록합니다. K-9 catalog에만 있는 jsoup·okio의 실제 사용이
미확인이므로 실제 빌드 의존성으로 조회·대조하지 않습니다. 이전 TN 3 결과는
현재 스냅샷에 적용되지 않습니다. catalog만으로 포함 여부를 인정하지 않고
해결된 빌드 의존성·SBOM 근거를 제공해야 합니다.

| 고정 소스 | 원래 → 남은 오류 파일 | 호환 파일 | 분석 / 건너뜀 / 본문 없음 |
| --- | ---: | ---: | ---: |
| NewPipe | 0 → 0 | 0 | 4,471 / 0 / 264 |
| AntennaPod | 0 → 0 | 0 | 4,404 / 0 / 172 |
| K-9 Mail | 6 → 1 | 5 | 10,925 / 1 / 699 |
| Nextcloud iOS | 2 → 2 | 0 | 2,700 / 4 / 0 |
| Firefox iOS | 78 → 66 | 14 | 26,858 / 41 / 3 |
| Ice Cubes | 2 → 0 | 2 | 1,037 / 0 / 0 |

6개 모두 검사 완료했지만 감사는 모두 불완전합니다. Objective-C로 iOS 함수
목록이 늘었고, 구문 호환은 원본 좌표·부분 분석을 유지합니다. 함수 수는 보안
탐지 재현율이나 모든 closure·initializer·native 함수를 측정하지 않습니다.
없는 Deferred plist와 미지원 구문도 표시합니다. 원래 OS 정답은 9 / 11,
이전에 추가한 CVE 하나의 분기 사례는 별도 14 / 14를 유지했습니다.

[재평가 37896002067](https://github.com/ictechgy/apsa/actions/runs/37896002067)은
최초 구현과 같은 트리입니다. 보관한 정규 결과의 해시는
`fa401df04cf3cb212ecd869719975c1d23a557637ea7e941356968fd18a9ad88`입니다.
artifact `11600143330`(`public-coverage-replay`) digest는
`sha256:f10966d0c0008f1398c1f96aada5a0abde4044cdbe144c2fd7ee99371206d277`,
만료는 `2026-11-08T06:56:50Z`입니다. 새 OSV 수집·MobSF 재실행은 없습니다.

## 검증 상태

최종 런타임 리뷰는 로컬 `a74442044f960744197b1fea29d03de91cc01d60`, 공개
`9c2d5d5033132ee2113a2638e17d3225d2e7dbc8`, 공통 트리
`133b48e59bbf01bb2aad8458812020eee6ae157f`에 적용됩니다.
[CI 37899396137](https://github.com/ictechgy/apsa/actions/runs/37899396137)의
6개 job이 모두 통과했습니다. Linux·macOS × Python 3.11·3.12와 Linux·macOS
required OS 격리를 포함합니다. **서로 다른 테스트 873개**이며 일반 job은
870개 통과·명시적 OS probe 3개 skip, Linux required는 872개 통과·macOS
별칭 probe 1개 skip, macOS required는 873개 모두 통과했습니다.

OS probe는 형제·보고서 파일 읽기 거부, 입력 쓰기 거부, scratch 쓰기,
localhost 네트워크 거부, 원본 입력 교체 시 복사한 입력만 보이는지 검사합니다.
macOS 합성 Data 볼륨 별칭 probe는 skip 없이 실행됐고 형제·보고서 별칭 모두
거부했습니다. 초기화·import·archive descriptor에는 부모 폴더 자체만 허용하고
`/System` 전체 허용은 제거했습니다. 파서 표준입력도 닫습니다.
부모 CLI·MCP 클라이언트까지 격리했다는 뜻은 아닙니다.

일반 job 4개는 Ruff·Pyright·독립 corpus, wheel·sdist 반복 빌드, 의존성 고지,
깨끗한 오프라인 설치·CLI·MCP·패키지 스킬 검사를 통과했습니다. 잠긴 환경에서
실제 Objective-C grammar 설치와 양성·음성 fixture도 실행했습니다.

[생성 AAB 37899396256](https://github.com/ictechgy/apsa/actions/runs/37899396256)은
Android build tools 35.0.0·platform 35로 통과했습니다. `aapt2 dump xmltree`의
실제 컴파일 선언과 package·debuggable·cleartext·min SDK·target SDK 값 5개를
대조했습니다. [정규 결과](results/2026-10-09-next-generated-aab-verified.json) 해시는
`3517f530199988e1f451475cdf85fe0f1ea81deda251124d665e740ab23abfc3`입니다.
artifact `11601213138`의 만료는 `2026-11-08T07:30:35Z`, digest는
`sha256:a8f656669fd8c34c049deb91097d06ef6dafa78065f1e08fbb942b16917d07c8`입니다.
새 합성 base-only bundle이며 완전한 설치 split 검증이 아닙니다.

[독립 입력 재실행 37899396170](https://github.com/ictechgy/apsa/actions/runs/37899396170)과
[고정 재평가 37899396124](https://github.com/ictechgy/apsa/actions/runs/37899396124)도
같은 런타임 트리에서 통과했습니다. 이후 실행은 수집한 입력의 해시를 확인하고,
정답을 본 뒤 개발 재검증한 결과로 명시합니다. 선언 사실 4 / 4·선택한 CVE 판정
16 / 16과 기존 catalog 사용 미확인 2건의 보류를 유지합니다. 최초 독립 요약과
과거 결과를 바꾸지 않았습니다.

보관한 [독립 입력 재실행](results/2026-10-09-next-holdout-rerun.json) 해시는
`afbea375bd2a53845d5c11e625d6a25da311d1226418543a70e6c6069449f54d`이며
artifact `11601329508`의 만료는 `2026-11-08T07:30:53Z`, digest는
`sha256:556d0be909ff7cf306085a66d06aa5e33fbd5a6b1906a8901b1c012dac90baf2`입니다.
[최종 고정 재평가](results/2026-10-09-next-replay-rerun.json) 해시는
`837acc40ad40a059e06b2c08e41b8d55057b63a04c3a46532537fbaa2225eec1`이며
artifact `11602045160`의 만료는 `2026-11-08T07:32:19Z`, digest는
`sha256:9b2ed910b598259de2daf1b14c2dfbb5218abeeb695fecb2f1d43944f8be9ad7`입니다.

[코드 리뷰](reviews/2026-10-09-next-runtime-code.md)와
[구조 리뷰](reviews/2026-10-09-next-runtime-architecture.md)는 전체 구현 스냅샷을
독립적으로 확인하고 CI 실행을 승인했습니다. 당시 CI 미완료 조건도 원문에
보존합니다. 실제 실행한 것은 Codex 독립 리뷰이며 Claude·Devin·Agy 호출이
아닙니다. 이후 문서·근거 리뷰는 런타임이 같은 별도 스냅샷에 적용합니다.
개발 브랜치는 main 병합·태그·PyPI 게시 전입니다.

남은 범위는 AAB 리소스·기기 split 병합, native 명령 분석, 서명 인증,
Objective-C 전처리·동적 dispatch·`.mm`, 더 넓은 독립 보안 finding 정답과
실기기 검사입니다. 이런 누락은 검사 완료로 표시하지 않고 coverage에 남깁니다.

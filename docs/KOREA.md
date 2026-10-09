# 국내 점검 기준과 함께 쓰기

이 문서는 한국어가 원문입니다. APSA는 금융보안원 평가, 행정안전부 모바일 전자정부 앱 소스코드 검증,
ISMS-P 인증의 **증거 자료를 정리하는 도구**이며, 어떤 기준의 통과·인증을 판정하거나 대신하지 않습니다.
공공기관 조달에 필요한 CC 인증이나 보안기능확인서도 없습니다.

## 1. 기관 점검 항목을 APSA 증거와 연결하기

금융보안원 평가 항목 등 일부 세부 기준은 공개되지 않으므로 APSA에 내장하지 않습니다. 기관이 받은
기준의 항목 ID와 제목을 [체크리스트 템플릿](../examples/checklists/organization-template.toml)에 옮기고,
각 항목에 관련 OWASP MASWE ID나 APSA 규칙을 연결하세요.

```sh
apsa scan ./app --out audit.json
apsa reports export latest --format checklist --checklist my-items.toml --out checklist.md
apsa reports export latest --format checklist --checklist masvs-v2 --out masvs.json
```

항목별 상태는 다음 중 하나입니다.

| 상태 | 의미 |
| --- | --- |
| `findings` | 관련 APSA 검사에서 발견 항목이 있음 |
| `no-findings-in-checked-scope` | 관련 검사가 실행됐지만 발견이 없음. **통과가 아님** |
| `partial` | 관련 검사가 일부만 실행됨 |
| `not-run` | 관련 검사가 실행되지 않음 |
| `not-assessed` | APSA에 관련 검사가 없음. 다른 증거가 필요 |

## 2. 점검 → 개선조치 이력 (ISMS-P 2.8.2 등)

같은 대상을 반복 검사한 보고서들로 발견 항목별 최초·최종 관찰 시점과 해소 시점을 정리합니다.

```sh
apsa reports history ./app
```

"해소"는 이후 보고서에서 더 이상 관찰되지 않았다는 뜻이며, 같은 검사가 완료됐는지 커버리지를 함께
확인해야 조치 근거가 됩니다. 두 보고서를 직접 비교하려면 `apsa reports compare BEFORE AFTER`를 쓰세요.

## 3. 공급망 자료

`apsa reports export latest --format cyclonedx`는 발견한 의존성의 CycloneDX 1.6 SBOM과 CVE 대조
결과(VEX, 모두 `in_triage`)를 만듭니다. 소프트웨어 공급망 보안 가이드라인의 SBOM 관리에 참고 자료로
쓸 수 있지만, 완전한 빌드 목록이 아니며 별도 검토가 필요합니다.

## 주의

- 점검 기준의 문구를 APSA 규칙과 연결하는 일은 기관 책임자가 검토해야 합니다.
- `not-assessed` 항목(루팅·탈옥 탐지, 난독화, 키 관리 등 상당수)은 APSA 외의 동적 점검이나 수동 검토가
  필요합니다.
- APSA 결과를 "기준 충족", "점검 통과"로 표기하지 마세요.

# Project taint specifications and claim verification

English is the source of truth; a Korean summary follows.

APSA's source rules follow data within one function. Real apps often move an
untrusted URL through a parser or view model, or load it through their own
wrapper, so APSA misses those flows. A project taint specification lets a
reviewer, or an AI agent working for one, name those project functions. APSA
then decides deterministically whether a declared source reaches a sink without
a recognized guard. The specification adds no code and no patterns.

## Format

TOML or JSON, at most 64 KiB, 100 sources and 100 sinks:

```toml
version = 1

[[source]]
id = "call-link"              # lowercase letters, digits and hyphens
method = "currentLink"        # exact function or method name
receiver = "CallState"        # optional exact receiver name or type
returns = "url"               # url or text
note = "Deep link parsed in CallIntentParser.kt"

[[sink]]
id = "in-app-browser"
kind = "webview-load"         # webview-load or sql
method = "open"
receiver = "InAppBrowser"
argument = 0                  # zero-based argument that is loaded or executed
```

- A source's return value is untrusted in every function that calls it.
- A `webview-load` sink reports `AST-WEBVIEW-UNTRUSTED-URL` unless the value
  passed a recognized scheme-and-host guard. A `sql` sink reports
  `AST-SQL-CONCAT`.
- Findings stay `candidate` and record `project_specification` (ID and kind) in
  their evidence. The report records the specification's SHA-256 and IDs in
  `inventory.project_specification`.

```sh
apsa specs validate apsa-specs.toml
apsa scan android --specs apsa-specs.toml
```

MCP: `specs_validate(path)`, then `audit_scan(target, specs=path)` or
`audit_start(..., specs=path)`. The file must be inside an MCP root.

## Review before trusting

A specification changes what APSA reports. A wrong source creates false
positives; a missing one leaves flows unchecked. Review a proposed
specification like code, keep it in the repository, and approve baselines that
contain specification-derived findings only after that review. Findings caused
by a specification are candidates and are excluded from default policy gates.

## Verifying claims

`apsa verify TARGET --weakness MASWE-0035 --path app/src/CallActivity.kt --line 42`
(MCP `verify_finding`) checks a finding claimed elsewhere, for example by an AI
code reviewer, against APSA's evidence for the same target. It takes a MASWE or
CWE identifier, or an APSA rule, and uses the latest report for the target unless
`--report` or `--rescan` is given.

| Verdict | Meaning |
| --- | --- |
| `corroborated` | An APSA finding for a related check is at the claimed location (±3 lines). |
| `same-file-other-location` | Related APSA findings exist in the file, but not at the claimed line. |
| `not-observed` | Related checks ran without a finding there. This is not proof of absence. |
| `partial` | Related checks, or the file's parsing, were incomplete. |
| `not-run` | Related checks did not run for this target. |
| `not-assessed` | APSA has no related check for that weakness. |

APSA never refutes a claim. Use the result to decide what to review first.

The built-in Android SQL sinks also cover `SQLiteDatabase.delete`, `update`,
`query`, `rawQueryWithFactory` and `compileStatement`, and
`SQLiteQueryBuilder.appendWhere`. `ContentProvider` overrides (`query`,
`update`, `delete`, `insert`, `call`) treat their `String` and `Uri` parameters
as caller-supplied.

## 한국어 요약

APSA의 소스 규칙은 한 함수 안의 데이터 흐름만 따라갑니다. 프로젝트 taint 명세(TOML/JSON,
`version = 1`)는 검토자나 그를 돕는 AI 에이전트가 프로젝트 고유 함수를 이름으로 지정하게 합니다.
`source`는 반환값이 신뢰할 수 없는 url/text인 함수, `sink`는 `webview-load` 또는 `sql`로 쓰이는
함수와 인자 위치입니다. 패턴이나 코드는 받지 않으며, 실제 흐름 판정은 APSA가 결정적으로 합니다.
명세로 생긴 발견은 항상 `candidate`이고 증거에 명세 ID가 남으며, 보고서에 명세 SHA-256이
기록됩니다. 명세는 코드처럼 검토하고, 명세 기반 발견을 기준선에 넣기 전에 사람이 승인하세요.

`apsa verify`(MCP `verify_finding`)는 다른 도구나 AI 리뷰어가 주장한 발견을 같은 대상의 APSA
증거와 대조합니다. 결과는 `corroborated`, `same-file-other-location`, `not-observed`(부재의
증거 아님), `partial`, `not-run`, `not-assessed`이며, APSA는 주장을 반박하지 않습니다.

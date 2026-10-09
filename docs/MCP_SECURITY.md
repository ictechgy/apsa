# MCP security model

English is the source of truth; a Korean summary follows.

APSA's MCP server reads app source and builds that may be untrusted, on behalf of
a model that may be steered by that content. This page states what the server
does to limit that, mapped to the
[OWASP MCP Top 10 (2025, beta)](https://owasp.org/www-project-mcp-top-10/), and
what remains the client's or user's responsibility. It describes APSA 1.4.0.

## Fixed, inspectable tool surface

- The server speaks stdio only and opens no network listener.
- The tool set is fixed for the life of a process; `tools.listChanged`,
  `resources.listChanged` and `prompts.listChanged` are `false`.
- `capabilities` returns `tool_manifest_sha256`: the SHA-256 of the canonical
  JSON (sorted keys, no whitespace, UTF-8) of the APSA-owned tool surface, which
  is each tool's name, description, annotation hints and parameter shapes
  (types, defaults, enums, items, required names), sorted by name. Schema titles
  and other details the MCP SDK generates are left out, so the value follows
  APSA's definitions rather than SDK formatting. For 1.4.0 it is
  `fdb8e4a2fdcf13a35df71a9a7290336b50a2e7f7fad66eff782959b6b0ba9037` by default
  and `818ab0bab3202f364478d866d094cd035e7d7b5c60b252c256bb2ade37d79a79` with
  `--allow-runtime`. A test pins both values and recomputes them from the
  `tools/list` response; any change to a tool's name, description, parameters or
  annotations must update them deliberately.
- The value a server reports about itself proves nothing on its own. To check a
  running server independently, take its `tools/list` result and compute
  `mobile_audit.mcp_server.manifest_sha256(tools)` with a trusted APSA copy, or
  apply the same normalization, then compare with the hashes above.
- Annotations: read-only tools are `readOnlyHint` and `idempotentHint`; tools
  that write local reports or jobs are not read-only; tools that fetch public
  advisories or query OSV are `openWorldHint`; the device tools registered only
  with `--allow-runtime` are `destructiveHint` and `openWorldHint`. Annotations
  are hints that clients must not trust blindly.

## OWASP MCP Top 10 mapping

| Risk | APSA controls | Remaining responsibility |
| --- | --- | --- |
| MCP01 Token mismanagement and secret exposure | No API key, token or model credential is needed or stored. Runtime scenarios use test canaries. Model context omits source excerpts, storage dumps and screenshot bytes. | Secrets inside scanned apps can appear in finding metadata such as file paths and rule IDs. |
| MCP02 Privilege escalation via scope creep | `--root` is required and every target, report and job is checked against it; `--allow-any-root` must be explicit. Device execution tools exist only with `--allow-runtime` and preview unless `execute=true`. | Keep roots narrow; enable runtime tools only for authorized test devices. |
| MCP03 Tool poisoning | Tool descriptions are static code, pinned by a published manifest hash; no dynamic tool registration. | Verify the package source (below) and compare the `tools/list` hash with the published values after upgrades. |
| MCP04 Supply chain and dependency tampering | PyPI Trusted Publishing with attestations, repeated builds and release checksums; the MCP Registry entry is published from the tag workflow by OIDC. The GitHub Action pins every action by commit SHA and installs APSA's dependencies from the release's hash-locked `requirements-release.txt`. | `uvx apsa@1.4.0`, the plugin and the registry entry pin APSA itself but resolve its dependencies at install time without hashes. For locked dependencies install with `--constraints requirements-release.txt` (or `--require-hashes`) from the release, or use the Action pinned by commit SHA. |
| MCP05 Command injection and execution | Tools take structured arguments; subprocesses are argument lists, never a shell. Parsers run under resource limits and, where available, a Seatbelt/bubblewrap sandbox. Advisory and app text is never executed. | Clients that build shell commands from registry metadata must not use a shell. |
| MCP06 Prompt injection via contextual payloads | App files and advisory text are labelled untrusted data in the server instructions and every report context. Context omits source excerpts and is bounded (20 records, 64 KiB per page by default). | The model can still be influenced by file paths, titles and advisory summaries; keep a human in the loop for actions. |
| MCP07 Insufficient authentication and authorization | Local stdio only; authorization is the root check above. | The client process's OS user is the trust boundary. |
| MCP08 Lack of audit and telemetry | Scans, jobs, runtime runs and reassessments are stored with IDs, timestamps and input hashes in the local report store. | Read-only tool calls are not logged by APSA; use client logging if required. |
| MCP09 Shadow MCP servers | Official channels: PyPI `apsa`, MCP Registry `io.github.ictechgy/apsa`, the `apsa` plugin in the `ictechgy/apsa` marketplace. | Do not install look-alike names; check the publisher. |
| MCP10 Context injection and over-sharing | Paginated, filtered context; dependency query matches are reduced to name/ecosystem/version; no screenshots or excerpts. MCP scans are offline. Only `dependency_check`, `intelligence_sync` and `intelligence_get` with `refresh` contact the network (plus the opt-in runtime tools, which talk to a local device): OSV receives inventoried package names, ecosystems and versions; advisory and CVE records are downloaded. No app files or findings are sent. | Finding metadata is sent to the model provider chosen by the client; dependency names and versions go to OSV when online tools run; follow your data policy. |

## Known limits

- Tool output schemas are generic JSON objects; structure is documented, not
  enforced by a strict schema.
- The parser sandbox protects the host from the parser, not the MCP client or
  the parent process.
- Annotations, the manifest hash and server instructions cannot stop a client
  that ignores them.

## 한국어 요약

APSA MCP 서버는 신뢰할 수 없는 앱 소스·빌드를 읽으며, 그 내용에 영향을 받을 수 있는
모델을 대신해 동작합니다. 서버는 stdio 전용이고 네트워크 포트를 열지 않습니다. 실행 중 도구
목록이 바뀌지 않으며(`listChanged: false`), `capabilities`의 `tool_manifest_sha256`은 APSA가
정의한 도구 이름·설명·annotation·파라미터 형태를 정규화한 해시입니다(1.4.0 기본값과
`--allow-runtime` 값은 위 영어 본문 참조). 서버가 스스로 보고한 값만으로는 증명이 되지 않으므로,
`tools/list` 결과로 `manifest_sha256`을 직접 계산해 공개 값과 비교하세요. 읽기 전용 도구는 read-only·idempotent, 네트워크 도구는 open-world, 기기
실행 도구는 `--allow-runtime`일 때만 등록되고 destructive로 표시됩니다.

OWASP MCP Top 10 대응: API 키·토큰 불필요(MCP01), `--root` 필수와 런타임 도구 opt-in(MCP02),
정적 도구 설명과 매니페스트 해시(MCP03), Trusted Publishing·SHA 고정 Action과 해시 잠금 설치·OIDC
레지스트리 게시(MCP04, `uvx`·플러그인 설치는 의존성을 해시 없이 해석하므로 잠금이 필요하면
`requirements-release.txt` 사용), 셸 미사용과 파서 샌드박스(MCP05), 앱·공지 내용을 신뢰하지 않는 데이터로
표시하고 원문 발췌 없이 페이지 단위로 제한(MCP06, MCP10), 로컬 stdio와 root 검사(MCP07), 스캔·작업·
런타임 기록 보관(MCP08), 공식 배포 경로 명시(MCP09). 읽기 전용 호출 로그, 엄격한 출력 스키마,
annotation을 무시하는 클라이언트는 APSA가 통제하지 못합니다.

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
- `capabilities` returns `tool_manifest_sha256`, the SHA-256 of the served tool
  names, descriptions, input schemas and annotations (canonical JSON, sorted by
  name). For 1.4.0 it is
  `1f55e218265003e9cf17aff0281d3ad7c1a953f2c4f787ee4cde973173123818` by default
  and `403b82cf4343601f9b6ec605ad77966d88bd571f07ea37124ac3c968e7d33be7` with
  `--allow-runtime`. A test pins both values; any change to a tool's name,
  description, schema or annotation must update them deliberately.
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
| MCP03 Tool poisoning | Tool descriptions are static code, pinned by `tool_manifest_sha256`; no dynamic tool registration. | Verify the package source (below) and the manifest hash after upgrades. |
| MCP04 Supply chain and dependency tampering | PyPI Trusted Publishing with attestations, locked dependencies, repeated builds and release checksums; the GitHub Action pins every action by commit SHA; the MCP Registry entry is published from the tag workflow by OIDC. | Pin the version (`apsa@1.4.0`) or the action commit SHA. |
| MCP05 Command injection and execution | Tools take structured arguments; subprocesses are argument lists, never a shell. Parsers run under resource limits and, where available, a Seatbelt/bubblewrap sandbox. Advisory and app text is never executed. | Clients that build shell commands from registry metadata must not use a shell. |
| MCP06 Prompt injection via contextual payloads | App files and advisory text are labelled untrusted data in the server instructions and every report context. Context omits source excerpts and is bounded (20 records, 64 KiB per page by default). | The model can still be influenced by file paths, titles and advisory summaries; keep a human in the loop for actions. |
| MCP07 Insufficient authentication and authorization | Local stdio only; authorization is the root check above. | The client process's OS user is the trust boundary. |
| MCP08 Lack of audit and telemetry | Scans, jobs, runtime runs and reassessments are stored with IDs, timestamps and input hashes in the local report store. | Read-only tool calls are not logged by APSA; use client logging if required. |
| MCP09 Shadow MCP servers | Official channels: PyPI `apsa`, MCP Registry `io.github.ictechgy/apsa`, the `apsa` plugin in the `ictechgy/apsa` marketplace. | Do not install look-alike names; check the publisher. |
| MCP10 Context injection and over-sharing | Paginated, filtered context; dependency query matches are reduced to name/ecosystem/version; no screenshots or excerpts. | Finding metadata is sent to the model provider chosen by the client; follow your data policy. |

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
목록이 바뀌지 않으며(`listChanged: false`), `capabilities`의 `tool_manifest_sha256`으로 도구
이름·설명·입력 스키마·annotation을 확인할 수 있습니다(1.4.0 기본값과 `--allow-runtime` 값은
위 영어 본문 참조). 읽기 전용 도구는 read-only·idempotent, 네트워크 도구는 open-world, 기기
실행 도구는 `--allow-runtime`일 때만 등록되고 destructive로 표시됩니다.

OWASP MCP Top 10 대응: API 키·토큰 불필요(MCP01), `--root` 필수와 런타임 도구 opt-in(MCP02),
정적 도구 설명과 매니페스트 해시(MCP03), Trusted Publishing·잠긴 의존성·SHA 고정 Action·OIDC
레지스트리 게시(MCP04), 셸 미사용과 파서 샌드박스(MCP05), 앱·공지 내용을 신뢰하지 않는 데이터로
표시하고 원문 발췌 없이 페이지 단위로 제한(MCP06, MCP10), 로컬 stdio와 root 검사(MCP07), 스캔·작업·
런타임 기록 보관(MCP08), 공식 배포 경로 명시(MCP09). 읽기 전용 호출 로그, 엄격한 출력 스키마,
annotation을 무시하는 클라이언트는 APSA가 통제하지 못합니다.

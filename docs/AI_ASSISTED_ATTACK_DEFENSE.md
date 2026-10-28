# AI-assisted attack and reverse-engineering coverage

Research date: 2026-10-28. This is an engineering assessment for APSA 1.6.3,
not a claim that an app resists every automated attacker.

## What changed in the threat model

[REA's upstream project](https://github.com/morluto/rea) describes an agent-facing
CLI/MCP workflow over existing native, application and runtime inspection tools.
That reduces manual movement between tools; its advertised capabilities are not
an independent benchmark of attack success or proof that any app can be cloned.
No REA distribution or reverse-engineering provider was installed for this work.

[Microsoft's October 21 ARTEX assessment](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
describes automation of reconnaissance and credential/OAuth abuse in an observed
cloud campaign. This supports treating reusable credentials and excessive app
permissions as automation multipliers. It does not establish a mobile-app
compromise or make an APK scan a cloud-incident investigation.

The engineering inference is to assume shipped client assets can be inspected
and local decisions can be studied. Protect server authorization, credential
lifetime and access scope independently. Obfuscation can raise effort, but its
absence is not itself a vulnerability, as
[OWASP MASVS-RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/) states.

## Improvements in 1.6.3

| Exposure | APSA response | Evidence boundary |
| --- | --- | --- |
| Recognizable credentials in shipped text resources | A separate bounded `PACKAGED-CREDENTIAL-TEXT` pass inspects admitted APK/IPA text resources; credential-only source files have an explicit input channel. | Masked candidates, member paths and completeness diagnostics; no credential validation or API requests. |
| Text telling an assistant to ignore scope or execute commands | A fixed untrusted-evidence instruction accompanies report pages and exact finding contexts, including metadata-truncated pages. | Advisory labeling; root checks and runtime opt-ins remain the enforcement boundary. |
| Tampered or uncertain analysis inputs | Preserve descriptor-safe staging, parser resource/OS isolation, input identity and partial coverage. | A successful parser invocation is not an app security verdict. |
| Rapid reuse of an exposed client credential | Preserve credential type/severity and remediation context rather than treating every key-shaped string as proven account access. | Key validity, restrictions, privileges and server behavior require separate authorized verification. |

The credential pass addresses a concrete intake gap: the legacy package scanner
checked DEX/executable strings while source platform checks were skipped for
APK/IPA. Text assets could therefore fall between both routes. Existing source
matchers also advertised `.properties` and `.strings` that normal input admission
did not supply. The new channel keeps these files out of unrelated AST analysis.
See [analysis limits](ANALYSIS_LIMITS.md) for the exact supported representations.

This focus follows
[OWASP MASWE-0004](https://mas.owasp.org/MASWE/MASVS-STORAGE/MASWE-0004/) and
[Android's hardcoded cryptographic secrets guidance](https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets):
packaged resources can expose sensitive material to an app downloader. Provider
tokens, private-key markers and public client API identifiers do not establish
the same privileges. Review restrictions and rotation needs using the relevant
provider's guidance, such as
[Google's API-key recommendations](https://docs.cloud.google.com/docs/authentication/api-keys-best-practices).

## Existing protections and remaining verification

APSA already checks debug flags, exposed components, links, WebView flows,
transport trust, selected biometric bindings, native hardening and signing
evidence. New work extends those checks rather than substituting an "AI-safe"
score. Candidate, configuration-confirmed, version-affected and runtime-confirmed
evidence remain distinct.

Backend authorization, object-level access, rate limiting, service-principal
permissions, token revocation and account recovery cannot be certified from a
client package. They remain separate authorized server/identity tests. Static
absence of a credential pattern does not prove absence of secrets, and local
obfuscation or root-detection checks cannot establish those server properties.

Source WebView inspectability parity and explicit release debug-artifact
inventory remain potential follow-ups. Their absence is not silently counted as
a passed check. Integration with an autonomous offensive tool would require a
separate scope and operational design; this assessment adds no such executor.

For model-output boundaries, see [MCP security](MCP_SECURITY.md). For easier
delivery without expanding those privileges, see the
[desktop app roadmap](DESKTOP_APP_ROADMAP.md).

## Independent design discussion

Claude, Agy and Grok were consulted independently on 2026-10-28 using the public
sources above and a generic defense design. No repository source, app binaries,
reports or credentials were included. These are design critiques, not reviews
or approvals of the implementation.

Their useful additions were to require process-level time/memory containment,
limit match counts as well as bytes, preserve read/skip uncertainty, remove
credential prefixes/lengths or value fingerprints from evidence, and test desktop
sidecar isolation, framed IPC and child-process cleanup on a clean host. The
existing parser boundary and match caps remain; the credential matcher now uses
the fixed `[REDACTED]` marker, and desktop acceptance gates include those process
and IPC requirements. Whole-product redaction of arbitrary imported text,
binary-resource credential decoding and future GUI lifecycle guarantees still
need their own scoped implementation and validation; this discussion does not
silently mark them complete.

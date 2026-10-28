# Desktop app delivery roadmap

Status: planned, not a shipped desktop application. Updated 2026-10-28.
The design contract is [DESIGN.md](../DESIGN.md). A first macOS prototype is a
proposal based on the current host; target OS, publisher and UI toolkit remain
open decisions.

## Use the existing guided interface now

`apsa tui` and bare `apsa` already open the keyboard-driven Textual interface.
`apsa doctor` explains installed capabilities and missing tools. Neither implies
that a desktop bundle exists or that `doctor.offline_ready` tested OS sandbox
activation. Keep the existing CLI, CI and MCP workflows supported.

## Desktop MVP flow

1. Select an APK, IPA or source folder with a native picker. Show the exact path,
   input kind and local report location before starting.
2. Show offline capability checks and actionable missing-tool messages. A static
   audit needs no model account. Online intelligence and device actions are
   separate, explained opt-ins.
3. Run the existing background job, show its stage/progress and allow cancel.
   Preserve a failed or interrupted state and the last completed report.
4. Present findings beside coverage, evidence strength and limitations. A
   completed job or zero findings must not become "this app is secure".
5. Offer local comparison and user-selected JSON/Markdown/SARIF exports.

The initial bridge can invoke a pinned bundled CLI with argument arrays and
bounded JSON output:

```text
apsa --home APP_HOME --json doctor
apsa --home APP_HOME --json scan TARGET --background
apsa --home APP_HOME --json jobs status JOB_ID
apsa --home APP_HOME --json jobs cancel JOB_ID
apsa --home APP_HOME --json reports get REPORT_ID
apsa --home APP_HOME --json reports export REPORT_ID --format markdown --out DESTINATION
```

These are interface examples; paths and IDs come from the picker and validated
job responses. Use an absolute bundled executable. The desktop layer reuses
`jobs.py`, `audit.py`, `Store` and the existing parser boundary. It needs no
listening HTTP server, remote dashboard or second analysis engine.

## Packaging decision gate

The job and parser workers currently use `sys.executable -I -m ...`. A frozen GUI
executable is not automatically an interchangeable Python interpreter. Start
with an explicit bundled Python runtime and pinned APSA installation, then prove
worker imports, native parser libraries and cancellation outside the checkout.
This is a packaging proposal, not a selected GUI dependency.

Compare a Python-native window with a native/webview shell only after that
prototype works. A shell must constrain its process/IPC surface to the fixed
audit operations; report text cannot choose executables or arbitrary commands.
Render imported evidence as text. Use framed IPC with a maximum frame size
checked before allocating a payload; reject malformed messages. Prove parent
exit and cancellation stop the entire owned worker process group. Keep the
bundled runtime read-only and retain isolated interpreter startup without user
site-packages, `PYTHONPATH` or current-directory imports.
[PyInstaller's documentation](https://pyinstaller.org/en/stable/operating-mode.html)
describes self-contained, platform-specific bundles and the need to account for
dynamically imported modules; it does not establish APSA worker compatibility.

Current parser locking/isolation supports POSIX hosts and diagnostics identify
macOS/Linux. Windows needs its own process, limits, locking and isolation port
before a supported desktop build can be claimed. A cross-platform window toolkit
alone does not provide that port.

## Distribution acceptance gates

| Gate | Required evidence |
| --- | --- |
| Clean launch | A signed build on a fresh supported host, outside the checkout, without an existing Python environment or target SDK. |
| Worker custody | Exact bundled imports, native-library loading, real sandbox activation and honest activation failure; no retry without isolation. |
| User control | Correct selected-root binding, offline default, bounded progress, verified cancellation and crash recovery. |
| Report parity | Same evidence, findings and incomplete coverage as the CLI on fixed synthetic fixtures and ordinary public-app samples. |
| Upgrade | Report-store migration/backup, authenticated update metadata, pinned artifact digest, recoverable failed update and documented rollback. |
| Publisher | Combined-product license decision, bundled dependency notices, SDK/tool redistribution terms and publisher identity. |

For direct macOS distribution, budget for signing bundled executables, Developer
ID, Hardened Runtime, notarization and launch testing. Apple describes these in
[notarization guidance](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
and [distribution options](https://developer.apple.com/macos/distribution).
Notarization is not a product security audit or App Review. Do not change
Gatekeeper settings or remove quarantine to make acceptance tests pass.

SDK/parser acquisition, license acceptance, device boot/install/run and model
provider configuration remain explicit setup decisions. The onboarding screen
must not silently perform them. This roadmap does not publish an installer,
choose a signing identity or promise a release date.

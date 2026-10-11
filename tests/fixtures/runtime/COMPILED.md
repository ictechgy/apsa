# Fresh compiled acquisition fixtures

`build_evidence.py --out <new-directory>` copies trusted Android and iOS sources
outside the repository, builds an Android 36 APK and an iOS SDK 27 simulator app,
and records exact tool argv, status, stdout, stderr, versions and source/build
hashes. It signs only these new fixtures with a generated Android test key and
iOS ad hoc signing. No existing archive, signing identity or device is selected.

`acquire_compiled.py --out <new-directory>` compiles a JVM 17 JAR, launches a fresh
process and creates a new fixture store for each login, switch and logout case.
`runtime_model_sha256` identifies the JAR and is accepted only for constructor
injected synthetic acquisition. Its independent credential authority replays a
previous credential over IPC. Network completeness stays partial, so this model
cannot establish HTTP backend invalidation. Local residue and credential lifetime
are independent controls.

With `--simulator`, the harness compiles the owned `Instrumented.swift`, creates
and boots an explicit new iPhone 17 / iOS 27 simulator, installs the new app,
checks installed executable and Info.plist hashes and reads only that new app's
response file. A fresh session directory holds its synthetic state. Each request
binds session, capture, snapshot, account, state and transition, and the app checks
those fields before emitting its response. Delivery uses the fixture's explicit
argv handler; OS deep-link routing is unmeasured. Only the scoped fixture store
is complete. UI, logs and network are unsupported. Every returned new simulator
UUID is shut down and deleted during cleanup; existing devices are never listed.

Recorder reports contain observation hashes, lengths and marker labels. Raw app
responses and replay credentials are not copied into reports. Tool command
records contain only the newly generated fixture paths and challenges. These
fixtures measure their own synthetic behavior. Physical-device and backend HTTP
proof remain separate and unmeasured.

The optional simulator adapter is repository test tooling and requires the owned
source fixture. The explicit local defaults are JDK 17.0.20+8, Android build tools
36.0.0 and Xcode with SDK 27. Tests skip the JVM build when that JDK is unavailable.

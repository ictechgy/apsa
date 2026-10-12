# Fresh compiled acquisition fixtures

`build_evidence.py --out <new-directory>` copies trusted Android and iOS sources
outside the repository and builds new APK/simulator-app fixtures. It requires
explicit `--android-platform`, `--build-tools`, `--ios-sdk`, `--ios-runtime` and
`--ios-target` selectors. The iOS target must specify `arm64` or `x86_64`, an iOS
deployment version and the simulator ABI. `--jdk-bin` and `--sdk` are optional
explicit tool locations. JDK fallback uses `APSA_TEST_JAVA_HOME`, `JAVA_HOME` or
PATH; Android SDK fallback uses `APSA_TEST_ANDROID_SDK_ROOT`, `ANDROID_SDK_ROOT`
or `ANDROID_HOME`. Invalid or unavailable configuration is rejected before
creating output or invoking build processes.

The builder records source/build hashes and command/output digests, status and
byte counts. It signs only the new fixtures with a generated Android test key and
iOS ad hoc signing. It never selects an existing archive, signing identity or
device. The requested iOS runtime is declared metadata with
`ios_runtime_verified=false`; the builder does not list, create or inspect devices.

`acquire_compiled.py --out <new-directory>` compiles a JVM 17 JAR, launches a fresh
process and creates a new fixture store for each login, switch and logout case.
`runtime_model_sha256` identifies the JAR and is accepted only for constructor
injected synthetic acquisition. Its independent credential authority replays a
previous credential over IPC. Network completeness stays partial, so this model
cannot establish HTTP backend invalidation. Local residue and credential lifetime
are independent controls.

With `--simulator`, the harness requires explicit `--simulator-device-type`,
`--simulator-runtime` and `--simulator-architecture` (`arm64` or `x86_64`). It
compiles the owned `Instrumented.swift`, creates and boots a new simulator
in an owned custom `--set` under the new output directory, installs the new app,
checks installed executable and Info.plist hashes and reads only that new app's
response file. A fresh session directory holds its synthetic state. Each request
binds session, capture, snapshot, account, state and transition, and the app checks
those fields before emitting its response. Delivery uses the fixture's explicit
argv handler; OS deep-link routing is unmeasured. Only the scoped fixture store
is complete. UI, logs and network are unsupported. Every returned new simulator
UUID receives bounded shutdown and delete attempts during cleanup. Each operation
has a 15-second timeout; delete is attempted even when shutdown fails. Failures
are recorded as inconclusive cleanup, and cleanup errors do not replace the
original construction error. An unreadable new-device identity leaves cleanup
inconclusive without any global fallback. Existing/default device sets are never
used or listed.

Recorder reports contain observation hashes, lengths and marker labels. Raw app
responses and replay credentials are not copied into reports. Tool command
records contain command/output digests, byte counts and status only; they do not
retain argv, operator paths, stdout or stderr bodies. These
fixtures measure their own synthetic behavior. Physical-device and backend HTTP
proof remain separate and unmeasured.

The optional simulator adapter is repository test tooling and requires the owned
source fixture. The JVM adapter resolves an explicit `--jdk-bin`, then configured
`APSA_TEST_JAVA_HOME`/`JAVA_HOME`, then `javac` on PATH. It never searches developer
homes. Tests skip the JVM build when an explicitly available JDK cannot be found.
No simulator defaults, device discovery or SDK/device operations are performed by
the mocked boundary tests.

# Owned runtime verification fixtures

These deliberately vulnerable/fixed apps exercise Mobile Audit on **dedicated test
emulators/simulators**. They are not production applications and use no backend or
real accounts. The only installed package identifiers are:

- Android: `audit.fixture.runtime`
- iOS simulator: `audit.fixture.runtime.ios`

`build.py` uses the installed Android SDK build-tools 36.0.0/API 36, JDK 17+ and
Xcode's iOS simulator Swift compiler. It downloads no app dependencies. The iOS
archive is a simulator IPA; it is not a device/App Store distribution.

Reproduce from the repository root with explicit, already running devices:

```sh
uv sync --extra dev --frozen
uv run python tests/fixtures/runtime/verify.py \
  --android-device emulator-5568 \
  --ios-device 2F770DDD-DF47-4C78-96FA-A830CC81034B \
  --sdk "$HOME/Library/Android/sdk" \
  --out .omx/artifacts/product-runtime-verify \
  --ios-url-probe
```

Replace those identifiers with your own dedicated fixture devices. The verifier
does not create, boot, shut down or delete devices. It removes an existing copy of
these fixture packages before installation, and resets only their test data. It
leaves the final owned fixtures installed for review; remove them or discard your
dedicated devices after reviewing the evidence.

The output directory and files are private to the current user. It contains build
artifacts, the test-only signing key, source audit reports, scenarios, runtime
reports, screenshots and `summary.json`. Each case prints a concise JSON result.
Exit zero means all eight fixture cases produced the expected observations.

| Platform | Transition | Mode | Storage assertion | UI authentication assertion |
| --- | --- | --- | --- | --- |
| Android | Logout | Retained | Failed: account A canary remains | Failed: protected deep link exposes it |
| Android | Logout | Fixed | Passed for captured canary | Passed: target denies access |
| Android | Account switch | Retained | Failed: account A canary remains | Passed: account B target denies A's screen |
| Android | Account switch | Fixed | Passed for captured canary | Passed: account B target denies A's screen |
| iOS simulator | Logout | Retained | Failed: account A canary remains | Not run |
| iOS simulator | Logout | Fixed | Passed for captured canary | Not run |
| iOS simulator | Account switch | Retained | Failed: account A canary remains | Not run |
| iOS simulator | Account switch | Fixed | Passed for captured canary | Not run |

Every mode also requires a new transition marker after the baseline. A vulnerable
mode producing the expected failed audit assertion counts as a successful verifier
case: it demonstrates that the detector distinguished the retained and fixed
variants. Runtime findings are reported separately from the fixture's intentional
debuggable build configuration.

Android prepares account A through a fixture URL, captures its baseline, dispatches
logout/account switch and the protected link, and captures the result. Delivery is
supported by the target Activity reported by `am start -W` and a changed, app-scoped
UI marker. The local fixture logout test does not establish general authentication
security or test server-side token invalidation.

iOS seeds the canary on launch and automatically performs the selected transition
after four seconds. The verifier captures a baseline after one second and an after
snapshot after another six seconds. It checks storage/state only. UI text, logs,
clipboard, Keychain deletion and physical-device behavior are not tested. Screenshots
provide review context and are not interpreted as automated UI assertions.

`--ios-url-probe` optionally dispatches `mobileauditfixture://transition` after the
eight modes and looks for a newly created delivery marker in the owned app's
container. A successful `simctl openurl` command alone is reported as unconfirmed.
The probe records whether the marker was observed and whether manual OS confirmation
was used; the scripted verifier performs no manual confirmation. An unconfirmed
optional delivery probe does not turn eight successful storage cases into broader
iOS coverage.

Android verifies the installed APK hash against the audited APK. iOS verifies its
installed executable and Info.plist against the audited IPA, and the verifier separately records
Info.plist hashes and checks that the installed fixture mode flags match the built
ones. Executable identity alone does not establish a match for all bundle resources
or signing/configuration metadata.

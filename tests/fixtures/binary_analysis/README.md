# Binary analyzer ground truth

The Java sources in `unsafe/` and `safe/` were authored for Mobile Audit.
Their APKs are unsigned static-analysis fixtures, not installable release apps.
Both contain real DEX instructions compiled by javac 17 (`--release 8`) and Android
SDK build-tools 36.0.0 d8 against Android API 36. No Android classes are bundled.

Rebuild with an existing SDK and javac on PATH:

```sh
python tests/fixtures/binary_analysis/build.py --sdk "$ANDROID_SDK_ROOT"
```

The unsafe fixture calls SSL error `proceed`, enables both file URL settings and
WebView debugging, registers a bridge, writes an access token key to preferences,
and passes the retrieved token value to logging. The safe fixture disables the
settings, cancels SSL errors, stores/logs a theme, and includes security API names
as string literals. The branch case must not receive a proven constant argument.

These fixtures exercise call-site/argument evidence, not runtime exploitability.
Mach-O tests construct minimal format fixtures in memory; they are not signed or
executable app distributions.

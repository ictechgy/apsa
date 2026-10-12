# Device specifications for APK-set selection

`apsa scan application.apks --apk-set-device device.json` requires an explicit
device specification. APSA accepts the bounded JSON subset below, pinned to
[bundletool 1.18.3 devices.proto](https://github.com/google/bundletool/blob/1.18.3/src/main/proto/devices.proto).
It does not query a device, ADB, a local SDK, or a live device-spec service.

The original four-field form remains supported:

```json
{
  "sdkVersion": 34,
  "supportedAbis": ["arm64-v8a", "armeabi-v7a"],
  "screenDensity": 480,
  "supportedLocales": ["en-US", "ko-KR"]
}
```

These fields are required. SDK is an integer from 1 through 9999; density is
an integer from 1 through 10000. ABIs are an ordered preference list of 1–8
known Android ABI names. Locales are a list of 1–128 language, optional script,
and optional region tags, such as `en`, `zh-Hant`, and `en-US`. Duplicate ABIs
and locales, including locales differing only by case, are rejected. Boolean
values do not stand in for integers. Full BCP-47 extensions and preview SDK
matching are outside this subset.

## Richer bundletool JSON

The optional fields below accommodate the richer shape produced by
[DeviceAnalyzer in 1.18.3](https://github.com/google/bundletool/blob/1.18.3/src/main/java/com/android/tools/build/bundletool/device/DeviceAnalyzer.java).
Every submitted field is validated before APK selection:

| Field | Accepted value |
| --- | --- |
| `deviceFeatures`, `glExtensions` | Arrays of at most 1024 unique nonempty tokens |
| `deviceGroups` | Array of at most 128 unique nonempty tokens |
| `codename` | `"REL"` or `""`; preview codenames are rejected |
| `deviceTier` | Integer from 0 through 2147483647 |
| `sdkRuntime` | `{}` or an object containing only boolean `supported` |
| `countrySet` | Printable string of at most 256 characters, including empty |
| `ramBytes` | Integer from 0 through 9223372036854775807, or canonical unsigned decimal string in that range |
| `buildBrand`, `buildDevice`, `socManufacturer`, `socModel` | Printable strings of at most 256 characters, including empty |

Array tokens have at most 256 ASCII characters and start with a letter or
digit; remaining characters may be letters, digits, `_`, `.`, `:`, `=`, `+`, or `-`.
This includes package-manager feature versions and `reqGlEsVersion` entries.
Empty supplementary arrays are accepted. RAM strings match protobuf JSON's
int64 representation; signs, leading zeros except `"0"`, fractions, exponent
notation, and overflow are rejected. Wrapper fields such as `deviceTier` and
`countrySet` use their scalar protobuf JSON form, not `{"value": ...}` objects.
Null values, control/format/surrogate characters in printable strings, and
unknown fields are rejected. `deviceId` and `densityAlias` are not fields of
the pinned DeviceSpec schema and are rejected.

CLI JSON files must be regular files of at most 1 MiB, use strict UTF-8, and
contain one JSON object. Duplicate object keys are rejected at every level,
including inside `sdkRuntime`; nonstandard JSON numbers are rejected. Structured
API callers supply an object and receive the same field/type/cardinality
validation; a dictionary cannot preserve duplicate raw JSON keys, so callers
parsing raw JSON should use `parse_device_spec_json` before submitting it.

## Normalization and selection limits

Only SDK, ABI preference, density, and locales affect selection. Validated
supplementary values are retained immutably in memory and are excluded from
the report's `device_spec`, which remains the four selection dimensions.
Hardware descriptors and supplementary capability values are not emitted.
The `device_spec_normalization` report object records the pinned schema,
selection dimensions, and the names of supplementary fields validated but
not used for selection. Its `unsupported_toc_targeting: "rejected"` policy
makes that limitation explicit. Equivalent submitted field order and RAM
integer/string representations produce deterministic normalization; ABI
preference order remains meaningful.

Capabilities are not inferred absent from omitted fields and are not used to
claim installability. APK/module/variant targeting involving features, OpenGL,
texture compression, device tiers/groups, SDK runtime, country sets, or any
other unsupported dimension fails closed even when matching capability fields
are present. Unsupported targeting in unselected variants is also rejected.
APSA does not fall back to scanning arbitrary archive members. Selection and
merged analysis remain partial; installation and manifest merging are not
verified.

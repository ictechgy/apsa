# Approved device evidence

English is the source of truth for this note.

APSA never infers a device's patch state from app files. OS advisory decisions
that depend on a device use an observed environment: a prepared runtime session
on an owned test device, or a `--device-info` JSON that the operator captured
from an authorized device.

## What counts as evidence

| Platform | Observed values | Notes |
| --- | --- | --- |
| Android | `ro.build.version.release`, `ro.build.version.security_patch`, `ro.vendor.build.security_patch`, `ro.soc.manufacturer`, `ro.soc.model`, model and observation time | The SoC properties exist on Android 12 and later; empty values stay unknown. Chipset and kernel components use the vendor patch level when it is observed. |
| iOS / iPadOS | OS product (`ios` or `ipados`) and version from an authorized simulator or the operator's own capture | APSA does not automate physical iOS devices. A simulator cannot establish a physical device's patch state. |

The operator must own the device or hold written authorization, use a test
build, and keep the captured JSON with the report. A device observation
describes that device at that time; it does not extend to other devices of the
same model.

## Status

No physical Android or iOS device was used in this development work. Runtime
and environment code is exercised with synthetic adapters and fixtures. Physical
device results remain unmeasured, and no device-specific claim is made.

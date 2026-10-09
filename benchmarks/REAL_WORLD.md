# Public app source and CVE evaluation protocol

English is the source of truth. This evaluation is separate from the development
synthetic corpus. The detector is held unchanged until the initial results have
been captured. Application commits, selected source/configuration facts, package
versions and expected CVE states are frozen in real_world_cases.json.

Six public production app source snapshots cover Android (NewPipe, AntennaPod,
K-9 Mail) and iOS (Firefox, Nextcloud, Ice Cubes). Historical releases and current
source snapshots are identified by immutable upstream commit, not described as
the latest release. No claim about the security of a current shipping app follows
from these historical or development source files.

The evaluator downloads only public upstream source and vendor documents on a
disposable read-only GitHub runner. It never runs application code/build scripts,
contacts app backends, installs an app or reads user data. The scanner receives
text/configuration bytes repacked without modifications from the pinned archive;
media is excluded, and exact primary-file Git blob hashes are verified. The same
repacked ZIP bytes are sent to actual APSA CLI and the fixed MobSF service.

## Separate measurements

1. Whole-source execution: completion, basic repeat consistency, scanned bytes
   and files, per-rule coverage/incompleteness, native alert counts and elapsed
   workflow time. APSA findings and MobSF rule entries have different units and
   must not be ranked by raw alert count. Three repetitions do not establish
   statistical significance. APSA uses fresh processes, MobSF a warm service with
   two CPUs and 4 GiB, so elapsed time is not engine-only speed.
2. Six selected configuration facts: explicit cleartext/ATS declarations in the
   named primary files. They are not six exploitable vulnerabilities. Browsers,
   podcast apps and private-server clients may deliberately allow broad transport
   exceptions. Missing inspection of a selected configuration is not a correct
   negative. These source facts do not establish a merged release manifest.
3. Ten selected dependency inventory facts: literal/version-catalog/resolved-pin
   identity and version, plus externally defined Gradle variables. The labels are
   source declarations, not a compiled dependency graph. A fixed source version
   cannot establish what is shipped or whether a vulnerable feature is reachable.
4. Thirty-two independent package/CVE units: eight affected, nineteen unaffected
   for the selected CVE, and five deliberately unresolved inputs. Labels come from
   CNA/vendor release evidence, including two Okio patch branches and SwiftNIO's
   2026 patch, not from OSV query results. Wrong package groups, ecosystem changes,
   URL representations and fixed boundaries are retained. Other CVEs returned for
   a negative selected-CVE unit remain in its matching IDs and are not false
   positives for the selected label.
5. Four selected real-app CVE paths connect actual extracted dependencies to
   exact OSV querying and APSA correlation. AntennaPod's declared jsoup 1.15.1 is
   affected by CVE-2022-36033; selected NewPipe/K-9 jsoup versions and K-9 Okio are
   outside the named affected ranges. Failure to extract/query a dependency is
   counted as an end-to-end miss for a known affected label, not a true negative.
6. Eleven OS correlation fixtures use real Apple/Android documents with newly
   generated environment data. They cover patch boundaries, missing device facts,
   simulator limitations, unlisted releases, invalid patch dates and unsupported
   custom CNA ranges. Safe abstention is distinguished from matching coverage.
   They are not observations from actual devices or exploit reproductions.

## Frozen public intelligence

The actual APSA query_dependencies and correlate functions are exercised. Public
OSV HTTP response bytes are captured once with exact request payload/status/hash,
then replayed for repetitions. This measures query integration, normalization,
identity handling and report correlation; APSA delegates package/version range
matching to OSV. It does not benchmark an independent APSA range database against
OSV or prove feed completeness. The primary CNA/GitHub records are pinned in the
repository, and vendor HTML snapshots and query bodies are retained in artifacts.

Failures, unknowns and unstable runs are never true negatives. Completed-case
recall is reported with end-to-end recall including failed affected units.
Unresolved cases have a separate abstention measure. Entire app vulnerability
precision/recall is undefined without an exhaustive independent truth set.
Convenience sampling and selected facts prevent general production-accuracy or
market-ranking claims. No commercial scanner, binary build, device, AAB/IPA,
reachability or undisclosed-zero-day capability is scored here.

The workflow preserves the original raw public reports and fixed input hashes.
If a gap is repaired afterward, results on these now-observed inputs must be
labeled development reruns; initial findings and fixed labels remain available.

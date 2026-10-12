# IPA signature evidence and its limits

APSA keeps three independent statements: agreement of code/resource hashes,
cryptographic CMS binding of exact bytes, and a certificate chain to explicit
policy anchors. None establishes Apple signer identity or app authenticity.
These are inspection results for supplied bytes under the stated scope.

## Explicit-anchor chain evidence

`cms_verification.certificate_chain_verified` is retained for compatibility.
Its explicit alias is `explicit_anchor_chain_verified`; both are the same boolean.
`certificate_chain_verified_alias` names that alias, and `chain_scope` is
`explicit-anchor-cryptographic-chain-only`. The code-signature summary also exposes
these fields so consumers do not need to infer their meaning from the old name.

`chain_anchor_origin` distinguishes `explicit-policy-anchors`, `none`, and
`unsupported-policy`. Anchors come only from the caller's validated, bounded
policy. No host trust store, keychain, account, or downloaded certificate is
used. The summary records anchor hashes and the policy hash; it does not export
anchor DER or signer identity claims.

`verification_time_basis` is `explicit-policy-epoch` when a policy epoch is
supplied, `verifier-current-time` for a valid policy without one, and `not-run`
when no supported policy exists. `verification_time` retains the supplied epoch
or the `current-time` marker. The marker describes the verifier's time basis,
not a measured historic signing time or a trusted timestamp. A policy supplied
to an unavailable/failed verifier describes the requested basis and does not
assert that chain verification ran successfully.

The explicit chain check uses OpenSSL purpose `any`. Its summary states
`cryptographic-chain-only`, `openssl_purpose=any`,
`apple_critical_extensions=not-validated`, `revocation=not-checked`, and
`apple_identity_policy=unsupported`. Successful generic chain verification does
not validate Apple-specific signer-purpose policy or critical extensions.
`apple_critical_extensions_verified`, `signer_purpose_policy_verified`, and
`revocation_checked` remain false. `apple_signer_trust` remains unverified and
`app_authenticity_verified` remains false in every result.

A separately isolated chain check may recognize an explicit anchor's hash as a
pinned public Apple root identity. `apple_root_anchor_chain_verified` is still
only a chain-to-that-root statement. It never promotes the Apple signer identity
or app-authenticity fields, even if a generic explicit-anchor chain succeeds.

## CMS binding of CodeDirectories

The CMS verifier checks the **exact primary CodeDirectory bytes**. It preserves
the original CMS bytes, applies bounded structural validation, and passes the
original bytes to the verifier. It does not reconstruct signed attributes.
`cryptographic_signature_verified=true` means this exact-primary binding passed;
it does not mean every directory in the superblob is bound.

Each `code_directories` row records its `slot`, `directory_role`, a byte digest
`directory_sha256`, `cms_bound`, and `cms_binding_state`.

| Directory | Binding evidence |
| --- | --- |
| Primary slot 0 | `cms_bound=true` only after exact primary CMS verification; state `verified-exact-primary` |
| Recognized alternate slots 0x1000 through 0x1004 | `cms_bound=false`; state `unverified-signed-cdhashes-attributes` |
| CodeDirectory in an unsupported slot, or wrong-format declared directory slot | Visible unbound/unverifiable metadata; no promotion to primary |

APSA does not yet validate the signed CDHashes attributes that can bind alternate
CodeDirectories. Alternates therefore remain unbound even if their page hashes
agree, their bytes equal the primary, or their identifiers/flags appear sensible.
The byte digest is provenance, not proof of CMS authentication. The same applies
to alternate metadata such as identifiers, team claims, and flags.

`cms_binding_complete` requires at least one directory and proven binding for
every relevant directory row. `cms_binding_state` is `complete` only when that
condition holds; otherwise it is `partial`. Exact primary verification is
preserved independently. `signature_integrity=cms-and-code-consistent` now
requires complete CMS binding **and** consistent checked code hashes. Multiple
directories consequently keep the overall status `partial` until their bindings
are proven. Actual invalid CMS or changed code retains `invalid-cms` or
`modified-code` respectively.

All declared/observed directories remain visible under the existing superblob
entry budget; no row is dropped by a directory-list limit. Unsupported extra
slots cannot be silently ignored to promote the aggregate. Duplicate slots,
overlapping/out-of-bounds blobs, malformed index tables, and byte/node/depth
budgets retain the existing fail-closed handling. An alternate without a primary
is never substituted as detached CMS content.

## Synthetic regression evidence

Tests generate fresh synthetic chains, keys, directories, Mach-O bytes, and
archives in temporary directories. They mutate alternate identifiers and flags
while leaving primary and CMS bytes unchanged. Primary CMS verification remains
true, code-page hashes remain consistent, alternate `cms_bound` stays false, and
overall `signature_integrity` remains partial. Mutating the primary metadata
with unchanged CMS instead invalidates CMS binding. Additional tests cover
unsupported/malformed directory slots, absent primary directories, and Mach-O
postprocessing so it cannot restore an incorrectly complete aggregate.

No genuine signer files, retained application inputs, certificate stores,
devices, or network verification are used. This is a metadata and binding-scope
strengthening; it does not implement full Apple identity, provisioning,
revocation, alternate signed-attribute, or app-authenticity verification.

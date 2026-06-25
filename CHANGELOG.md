# Changelog

## 0.3.0 - 2026-06-25

### Added

- Added wasm support for building and signing agent grant delegations. The signer emits the same canonical binary wire format verified by the Rust protocol implementation, including deployment scope, agent KEM public key, delegate signer key id, delegation window, maximum grant TTL, delegation epoch, and per-secret grant entries.
- Added client-side validation for delegated grant inputs, including NFC string validation and protocol field-size limits for delegate signer ids, secret fields, and wrapped item keys.

### Security

- Delegated grant entries include the wrapped item key bytes in the signed canonical payload so a grant issuer can only select user-authorized entries verbatim and cannot re-wrap secret material to a different key.
- Resolve-only secret entries can be represented without proxy egress rules, while egress-bearing entries remain explicit in the signed payload.

## 0.2.0 - 2026-06-12

### Added

- Added `protocol::membership_grant`, a shared helper for signing and verifying vault membership grants. The signed payload is a fixed protocol commitment: `"seren-secrets/membership-grant" || vault_uuid(16) || identity_uuid(16) || access_level_byte(1) || wrapped_vault_key`.
- Added resolver support for signed vault membership grants.
- Added wasm `kdfValidateStoredParams` for validating stored Argon2id profiles.
- Added `seren-secrets-macros` with `#[derive(RedactedDebug)]` for redacted `Debug` implementations on secrets-bearing structs.
- Added `ZeroizableJson` and `ZeroizableBTreeMap` container wrappers for plaintext JSON blobs and map keys/values that must scrub with decrypted item content.
- Added `ResolverError::InvalidInput`; exhaustive matches must add an arm for it.

### Changed

- Resolver references now require canonical hyphenated UUIDs, exactly one field segment, and no query, fragment, or whitespace.
- Bounded raw wasm `kdfDeriveKey` resource parameters before derivation so untrusted inputs cannot request excessive memory, time cost, parallelism, output size, or salt length.
- Changed `membershipGrantSign` to use the shared `protocol::membership_grant` implementation instead of duplicating the byte layout locally.
- Improved zeroization of transient key buffers on account unlock, vault-key unwrap, item content-key unwrap, attachment-key unwrap, backup import/export, recovery-key parsing, and recovery flows.
- Implemented `Zeroize` for `ItemContent` and every field type so decrypted item bodies can be scrubbed after use; decrypted item bodies now return in a zeroizing guard by default.
- Changed item-content `raw_import` fields to `ZeroizableJson` and API credential `headers` to `ZeroizableBTreeMap<String, String>` while preserving their serialized JSON shape.
- Redacted imported plaintext from `Debug` output for imported items and attachments.
- Documented the pinned blind-index normalization behavior.
- `grant_membership` now requires the granter identity signing private key.
- `decrypt_item_with_content_key` now returns `DecryptedItemContent`; call `into_inner()` to take owned plaintext.
- Account setup now rejects KDF profiles that unlock and recovery would reject. This affects newly minted account bundles only; it does not change how existing stored account secrets are decrypted.

## 0.1.0 - 2026-06-03

### Added

- Initial Seren Secrets workspace with crypto, resolver, and wasm crates.
- Added account setup and unlock flows, recovery keys, vault key wrapping, item encryption, attachment encryption, blind indexes, signing helpers, and resolver request signatures.
- Added import and export support for encrypted backups and common password-manager import formats.

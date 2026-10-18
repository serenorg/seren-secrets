# Changelog

## [0.6.0] - 2026-10-18

### Added

- Add the generic multi-principal agent delegation contribution protocol in `protocol::agent_delegation_policy`, with WASM `agentDelegationContributionPayload` and `agentDelegationContributionSign`. The shared canonical payload binds the request and result, destination organization, scope, deployment and revision, agent identity and key fingerprints, participant, decision, field mappings, vault grants, expiry, and request nonce.
- Add optional `vault_provisioning` commitments to delegation contributions. A provisioning contribution signs an opaque proposal binding, the exact key-to-vault map including each `adopted` flag, and exactly matching `write` grants with an `until_revoked` lifetime, for at most `MAX_PROVISIONED_VAULTS` vaults. A decline carries no map or grants. Contributions that omit `vault_provisioning` sign the same bytes as before. This release provides only the signed contract; proposal validation, vault provisioning, and approval workflows belong to the consuming client and service.
- Add context-bound identity signatures through Rust `signing::sign_with_context` and `signing::verify_with_context` and WASM `identitySign` and `identityVerify`. Signatures cover the `seren-secrets/context-signature` domain, a 1 to 255 byte printable non-space ASCII context, and the application message, so they cannot verify as a library protocol payload or under another context. Opaque identity key handles still never sign caller-supplied raw bytes.
- Add `VaultClient::trash_item`, which uses the trash-only route, returns `TrashOutcome::Trashed` or `TrashOutcome::AlreadyTrashed`, and never permanently deletes an item.
- Add `VaultClient::list_items_in_state` with `ItemListState::Active` and `ItemListState::Trashed`. Summary scans never read item bodies. A trashed scan requires the service to return the actual `trashed_at` timestamp and rejects summaries that contradict the requested state.
- Add `VaultClient::list_attachments`, `get_attachment`, `put_attachment`, and `delete_attachment`. Attachments use a fresh per-attachment key, the existing attachment AAD prefixes bound to both the item and attachment identifiers, and the existing size limits. Plaintext attachment bytes and names stay in zeroizing buffers.

### Changed

- **Breaking:** Replace `protocol::agent_grant_delegation` (`AgentGrantDelegation`, `AgentGrantDelegationEntry`, `AgentGrantDelegationScope`, and `sign_agent_grant_delegation`) and WASM `agentGrantDelegationSign` with the generic contribution protocol. The new canonical payload is not compatible with the removed format, so upgrade contribution producers and verifiers together.
- **Breaking:** `SerenSecretsResolverConfig` now requires `network`. Select `ResolverNetwork::HostEnvironment` to keep the previous behavior: environment proxies, redirect following, and HTTPS except for loopback hosts. `ResolverNetwork::Direct` ignores proxies, never follows redirects, and accepts HTTP or HTTPS base URLs without credentials, query, or fragment, including plain HTTP to non-loopback hosts. Use `Direct` only where the caller controls that transport.
- **Breaking:** `VaultClient::update_item` takes an optional `jiff::Timestamp` revision; pass `None` for an unconditional update. A supplied revision is sent as a weak `If-Match` ETag. `ResolverError` adds `Stale`, `Rotating`, and `KeyVersion` for stale revisions, vault key rotation, and key version conflicts; handle them in exhaustive matches.
- **Breaking:** `VaultClient::list_items` returns active `DecryptedItemSummary` records instead of `(Uuid, String)` tuples. `DecryptedItem` adds `updated_at` and `trashed_at`, and the wire `ItemSummary` adds `trashed_at`. Use the named summary fields and update Rust struct literals for the added fields. Reads reject a missing or malformed `updated_at` and a malformed non-null `trashed_at`; trashed scans also reject a missing or null `trashed_at`, and active scans reject a non-null one. Upgrade the service summary contract before enabling trashed scans.
- **Breaking:** `LoginUrl` adds optional `label` and `primary` fields. Use `LoginUrl::plain` or set the new fields in Rust struct literals. Existing JSON remains valid, and absent values stay omitted when serialized.

### Removed

- **Breaking:** Remove the `seren_secrets_crypto::import` module (the 1Password `.1pux`, Bitwarden, KeePass, CSV, and `otpauth://` parsers and `ImportedItem`) and the WASM exports `importOnePassword1pux`, `importBitwardenEncryptedJson`, `importBitwardenJson`, and `importKeepassXml`. Applications that import provider exports must parse them in their own adapters, map them into the typed item bodies, and encrypt them with this crate. Account, vault, item, attachment, recovery, and backup encryption formats and AAD prefixes are unchanged.

### Fixed

- `VaultClient::move_item` now trashes the source through the trash-only route instead of `DELETE` after copying it, so a source that is already in the trash is never permanently deleted. The service must provide the trash-only route.

### Security

- Update rustls to 0.23.46, with the required rustls-webpki and aws-lc updates, to address dependency advisories, and replace the yanked chacha20 0.10.1 with 0.10.2. Removing the import parsers also removes the ZIP and XML parser dependencies. Existing crypto wire formats and known-answer vectors are unchanged.

## 0.5.0 - 2026-08-05

### Added

- Added `hostedAgentSign` to the wasm API. It signs hosted employee identity requests with the account signing key. Hosted identities carry no client-provided public keys, so their canonical payload is distinct from `createAgentSign`.

### Changed

- **Breaking:** Added `nonce` to `protocol::resolve::ResolveRequest` and to its canonical signed bytes, which now end with a `nonce=<uuid>` line. The `/resolve` request body carries the same nonce. Clients and services must upgrade together. Use a fresh random nonce for each resolution request.
- **Breaking:** The resolver now sends only the bearer credential and signed request body to `/resolve`. Services must derive caller and organization context from the bearer credential. The resolver no longer forwards correlation metadata.
- **Breaking:** Secret field resolution now returns `ResolverError::UnknownField` for empty values, missing array entries, unmatched labels, and malformed selectors. References such as `${emails[5]}` that previously resolved to an empty string now fail. Before upgrading, inspect indexed and optional-field references. Correct each reference that can select a missing or empty value.
- **Breaking:** `VaultClient::list_vaults` now returns an error when a vault record the caller holds a wrapped key for cannot be unwrapped or parsed. It no longer omits the record silently.

### Security

- Each signed resolution request includes a fresh nonce. The service can consume the nonce once and reject a replayed request.
- Resolver field extraction and vault listing fail closed instead of returning empty or partial results.

## 0.4.0 - 2026-07-17

### Added

- Moved agent grant delegation signing into the shared crypto crate and exposed it to native clients while keeping the existing wasm API as a thin wrapper. Both surfaces now use one canonical encoder and known-answer vector.

### Changed

- **Breaking:** Replaced `ResolverError::ControlPlaneUnavailable(String)` with the topology-neutral `ResolverError::Transport(TransportError)`. Transport failures expose stable timeout, connection, and other classifications while preserving the originating error through `Error::source()` without making the concrete HTTP client type part of the resolver error API.
- Updated the cryptographic dependency stack to `chacha20poly1305` 0.11, `ed25519-dalek` 3, `x25519-dalek` 3, and `getrandom` 0.4 while preserving the existing wire formats and known-answer vectors.

### Security

- Resolver errors no longer expose upstream response bodies or transport details through `Display` or `Debug`. Server error bodies remain available for structured handling.
- Updated `quick-xml` to 0.41.0 to address RUSTSEC-2026-0194 and RUSTSEC-2026-0195 in XML import processing.

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

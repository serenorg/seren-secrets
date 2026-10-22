# Seren Secrets

Seren Secrets is the public client-side crypto and resolver foundation for Seren's end-to-end-encrypted secrets system. Trusted hosts can resolve `seren-secrets://...` references without giving services access to plaintext secret values.

Services store ciphertext, wrapped keys, public keys, and the operational metadata required to authorize access. This repository contains the code that derives keys, unwraps encrypted envelopes, signs protocol requests, parses item bodies, and resolves approved references.

## Trust model

Servers and import files are untrusted inputs. They can return malformed, replayed, substituted, or tampered bytes. The client protocol rejects invalid envelopes before it exposes decrypted material. Resolver hosts must authenticate and authorize callers before they return plaintext.

## Crates

- `seren-secrets-crypto` - pure Rust protocol and crypto crate. It owns key derivation, encrypted envelopes, signatures, canonical authorization formats, encrypted backups, and typed secret item bodies. It performs no I/O and has no async runtime dependency.
- `seren-secrets-crypto-wasm` - wasm-bindgen bindings for browser clients. It includes account, vault, item, membership, agent identity, and agent delegation operations.
- `seren-secrets-resolver` - host resolver and vault client. It signs each resolution with a fresh nonce, calls the service, unwraps envelopes locally, and returns plaintext to the approved caller.
- `seren-secrets-sidecar` - optional resolver binary for non-Rust hosts. It provides an authenticated local loopback process.

## Security invariants

- Private keys, account keys, vault keys, and item content keys are client-side material.
- AAD prefixes are protocol commitments and must change only in coordinated protocol updates.
- Wrapped keys and ciphertext bodies are opaque to services.
- A resolution signature binds the reference, caller identity, issue time, and a fresh nonce. The service consumes each nonce once to reject replayed requests.
- Empty, missing, or malformed fields cause secret extraction to fail. An invalid accessible encrypted record causes vault listing to fail.
- Vault membership grants are signed by the granter identity. The signature binds the vault id, grantee identity id, access level, and wrapped vault key so grant records are attributable and tamper-evident.
- Membership grant signing is additive metadata. It does not change existing account, vault, item, attachment, recovery, or backup encryption wire formats.
- Agent delegation contribution payloads bind the request, policy, target, scope, mappings, participant, decision, expiry, and nonce without encoding product-specific participant names or workflows.
- Opaque identity key handles do not sign caller-supplied raw bytes. Application-defined messages are signed under a library-owned domain and a caller-chosen context label, so those signatures cannot verify as library protocol payloads.
- Hosts must zeroize or drop resolved plaintext after the approved operation is complete.

## Granting vault membership

Use `seren-secrets-crypto::protocol::membership_grant` to create or verify vault membership grants. The canonical payload is:

```text
"seren-secrets/membership-grant" || vault_uuid(16) || identity_uuid(16) || access_level_byte(1) || wrapped_vault_key
```

The access-level bytes are fixed protocol data: `read = 1`, `write = 2`, and `admin = 3`. The vault client helper `grant_membership` wraps the vault key for the grantee. It signs the payload with the granter identity signing private key. Then it sends the grant to the service.

## Approving agent delegation

Use `seren-secrets-crypto::protocol::agent_delegation_policy` to construct the canonical bytes for one participant's contribution to a multi-principal agent delegation. The shared builder binds the exact agent keys, target, scope, mappings, vault grants, participant, decision, expiry, and request nonce. Browser clients use the wasm `agentDelegationContributionPayload` export and sign the returned bytes with the participant identity key; the Passwords service independently reconstructs the same payload before it accepts the signature.

## Signing agent identities

For identities with client-provided encryption and signing public keys, browser clients use `createAgentSign`. For hosted identities without client-provided public keys, browser clients use `hostedAgentSign`. These functions use distinct canonical payloads and sign them with the account signing private key.

## Signing application-defined messages

Use `seren-secrets-crypto::signing::sign_with_context` and `verify_with_context` when an application needs an identity signature over a message format it defines. Browser clients use the wasm `identitySign` export with an opaque identity key handle, such as the one returned by `unlockAccount`, and `identityVerify` to check the result. The signed bytes are:

```text
"seren-secrets/context-signature" || context_len(1) || context || message
```

The context is 1 to 255 printable non-space ASCII bytes. Choose a distinct context for each message format. The application owns the message encoding: it must be unambiguous and must bind every value the verifier relies on.

## Client application formats

Foreign password-manager imports, provider-specific synchronization metadata, and provisioning proposals belong to the client applications that offer them. The public crypto and WASM APIs expose typed item bodies and canonical authorization primitives; they do not parse provider exports. Clients that parse such exports map them into the typed item bodies and encrypt them with this crate.

## Vault client

`seren_secrets_resolver::vault::VaultClient` provides encrypted vault and item operations, identity and membership helpers, approval polling, and attachment HTTP operations. `VaultClientConfig` requires the actual caller identity id, a key source, bearer credential, and explicit `ResolverNetwork` policy. `HostEnvironment` allows HTTPS or loopback HTTP and uses host proxy settings. `Direct` accepts a host-authorized HTTP(S) endpoint without credentials, queries, or fragments and disables proxies and redirects. Call `ResolverNetwork::validate_endpoint` before credential-bearing bootstrap requests.

The public `vault::attachments` module exposes bounded wire mapping, upload preparation, metadata decryption, and blob verification for adapters that own their transport. Hosts own caller authorization, session refresh, reprompt checks, lock invalidation, plaintext lifetime, and explicit file saves. Upload and download buffers use zeroizing storage. Error formatting redacts server bodies and transport details; retained upstream bodies must never be logged. Crypto algorithms, encrypted formats, and AAD bindings remain in `seren-secrets-crypto`.

## Conditional vault operations

The resolver vault client accepts an optional borrowed `ItemRevision` for item updates and trash operations. `ItemRevision::new` validates RFC3339 while preserving the original offset and fractional precision; reads, writes, serialization, and conditional headers retain that exact representation. Obtain revisions from service responses rather than the local clock. Stale revisions are refused, rotation is reported separately, and the trash operation never permanently deletes an item. Item summaries expose actual lifecycle timestamps without reading item bodies. Item `trashed_at` and attachment `created_at` are `ServiceTimestamp` values: validated like revisions and kept in the service's exact text, but never usable as revisions. Attachment operations encrypt and decrypt locally with the shared per-attachment protocol and bind both item and attachment identifiers.

Item creation accepts a caller-chosen id and favorite flag. Updates accept `favorite: Option<bool>` and return the confirmed `updated_at`; `None` preserves the stored favorite. `trash_item` returns `TrashResult { outcome, updated_at }` for both a newly trashed item and an already-trashed item. Its revision comes from the write response; missing or invalid revisions fail explicitly. Convenience creates choose fresh ids and unfavorited metadata. Vault listings report only the caller's own active access.

Guarded attachment uploads take a caller-chosen attachment id and parent revision, and store the file's SHA-256 sealed under the attachment key. Guarded deletions also require the exact stored encrypted digest to match. Every guarded deletion outcome is decided by the service, including when local metadata is missing or unverifiable. Successful guarded responses return the exact parent revision supplied by the service. A repeated upload of the same file reports `AlreadyPresent` with the parent revision from the service's conflict response; when that response has no valid revision, the upload fails as malformed. Conflict and stale refusals without a response revision return `None`; the request revision is never substituted. Deploy service support that atomically enforces these conditions before enabling guarded methods: an older create endpoint may accept an upload while ignoring its guard. Ordinary attachment methods support explicit interactive operations.

## Attachment metadata and empty files

Attachments may contain zero plaintext bytes. Their authenticated encrypted envelope still contains the format prefix, nonce, and authentication tag, and counts toward the existing per-file and per-item limits. Filenames remain required.

`AttachmentUpload::content_type` and `AttachmentSummary::content_type` are optional. `None` is encrypted as an empty UTF-8 string using the existing content-type key, associated data, and envelope format; `Some("")` is rejected. No MIME type is invented. Existing nonempty encrypted strings remain readable as `Some`, and existing raw string decryptors read the absence representation as an empty string. Consumers must preserve absence rather than substitute metadata. Update clients that reject envelope-only attachment blobs before enabling empty-file uploads; existing encrypted records remain readable without a migration.

Encryption constructs the authenticated envelope in one owned buffer. Attachment requests can be converted into JSON with `serde_json::Value::from(request)`, which moves owned encrypted strings rather than cloning them. The resolver also consumes response envelopes without cloning the inner JSON. See [attachment memory measurements](docs/attachment-memory.md) for the reproducible benchmark scope and procedure.

## Provisioning grant commitments

Agent delegation contributions can sign an opaque vault provisioning binding and the exact key-to-vault mapping, including whether each vault was adopted. The shared canonicalizer checks the binding, mapping, write grants, deployment scope, and grant lifetime. Existing contributions without provisioning keep their original signed bytes. Provider names and proposal metadata are owned by the client application and are absent from this contract.

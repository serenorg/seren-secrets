# Seren Secrets

Seren Secrets is the public client-side crypto and resolver foundation for Seren's end-to-end-encrypted secrets system. Trusted hosts can resolve `seren-secrets://...` references without giving services access to plaintext secret values.

Services store ciphertext, wrapped keys, public keys, and the operational metadata required to authorize access. This repository contains the code that derives keys, unwraps encrypted envelopes, signs protocol requests, parses item bodies, and resolves approved references.

## Trust model

Servers and import files are untrusted inputs. They can return malformed, replayed, substituted, or tampered bytes. The client protocol rejects invalid envelopes before it exposes decrypted material. Resolver hosts must authenticate and authorize callers before they return plaintext.

## Crates

- `seren-secrets-crypto` - pure Rust protocol and crypto crate. It owns key derivation, encrypted envelopes, signatures, canonical authorization formats, imports, exports, and typed secret item bodies. It performs no I/O and has no async runtime dependency.
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

The access-level bytes are fixed protocol data: `read = 1`, `write = 2`, and `admin = 3`. The resolver helper `grant_membership` wraps the vault key for the grantee. It signs the payload with the granter identity signing private key. Then it sends the grant to the service.

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

## Managed vault provisioning

Managed vault provisioning adds an optional `vault_provisioning` field to an agent delegation contribution. When absent, serialization and canonical signature bytes remain unchanged. The extension binds an opaque proposal commitment (`keys`, `vault_count`, `payload_digest`), the fixed `until_revoked` lifetime, and a map of proposal keys to vault ids and adoption decisions. It is valid only for an existing hosted identity, an exact deployment and revision, empty secret mappings, and write-only vault access. An approval requires exactly one map entry and one grant per committed key; a decline carries neither. Generic writable delegation retains its expiry requirement.

`vault_provisioning_binding` validates the complete proposal and computes its SHA-256 commitment. Its browser equivalent is `vaultProvisioningBinding`. Proposals contain key, name, description, write access and a 1Password source account/vault pair. Canonical JSON sorts every object's keys, preserves array order, and uses compact JSON serialization. No names, descriptions or source ids belong in the server's binding. Clients must compare the computed binding before displaying the proposal or signing a contribution. The original agent-delegation domain and its complete canonical builder also cover the new map; there is no separate unsigned completion map.

The native fixtures under `crates/seren-secrets-crypto/tests/fixtures` pin both legacy and provisioning bytes. After a Node-target `wasm-pack build` of `crates/seren-secrets-crypto-wasm`, run `node crates/seren-secrets-crypto-wasm/tests/provisioning.cjs <package-directory>` to exercise the actual WASM exports and tamper rejection.

Land and release this producer before updating the Passwords service dependency and the Passwords UI's shared Secrets pin, generated WASM bundle and OpenAPI client. The service owns Core-authenticated setup consumption, atomic application, the immutable result map and completion retries. The browser owns proposal verification, encrypted vault creation/adoption and signing. An approval deadline bounds signing; it is not an applied grant TTL. Grant removal and the owning deployment boundary still revoke access.

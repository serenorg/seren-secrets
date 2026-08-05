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
- Agent grant delegations bind the user, organization, optional workspace, agent identity, approved fields, key wraps, validity window, and delegation epoch.
- Hosts must zeroize or drop resolved plaintext after the approved operation is complete.

## Granting vault membership

Use `seren-secrets-crypto::protocol::membership_grant` to create or verify vault membership grants. The canonical payload is:

```text
"seren-secrets/membership-grant" || vault_uuid(16) || identity_uuid(16) || access_level_byte(1) || wrapped_vault_key
```

The access-level bytes are fixed protocol data: `read = 1`, `write = 2`, and `admin = 3`. The resolver helper `grant_membership` wraps the vault key for the grantee. It signs the payload with the granter identity signing private key. Then it sends the grant to the service.

## Delegating agent access

Use `seren-secrets-crypto::protocol::agent_grant_delegation` to delegate selected secret fields to an agent. Each signed entry binds one vault, item, field, and wrapped item key. The delegation also limits its validity window and maximum grant lifetime.

The native `sign_agent_grant_delegation` and wasm `agentGrantDelegationSign` functions use the same canonical format. Inputs must use normalized strings, unique entries, valid time bounds, and the protocol size limits.

## Signing agent identities

For identities with client-provided encryption and signing public keys, browser clients use `createAgentSign`. For hosted identities without client-provided public keys, browser clients use `hostedAgentSign`. These functions use distinct canonical payloads and sign them with the account signing private key.

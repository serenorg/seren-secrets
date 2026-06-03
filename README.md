# Seren Secrets

Seren Secrets is the public client-side crypto and resolver foundation for Seren's end-to-end-encrypted secrets system. It supports hosts that need to resolve `seren-secrets://...` references without giving the server plaintext access.

The server stores ciphertext only. This repository contains the code that derives keys, unwraps vault and item envelopes, verifies request signatures, parses encrypted item bodies, and resolves approved secret references on trusted client hosts.

## Trust model

Servers and import files are treated as untrusted inputs. They may return or contain malformed, replayed, substituted, or tampered bytes, and the client-side protocol code is responsible for rejecting invalid envelopes before exposing decrypted material. Resolver hosts must authenticate and authorize callers before returning plaintext.

## Crates

- `seren-secrets-crypto` - pure Rust protocol and crypto crate. It owns the Argon2id KDF wrappers, XChaCha20-Poly1305 envelopes, X25519 sealed-box wraps, Ed25519 signatures, item/vault/share wire formats, AAD layouts, importers, export format, and typed secret item bodies. It performs no I/O and has no async runtime dependency.
- `seren-secrets-crypto-wasm` - wasm-bindgen bindings over `seren-secrets-crypto` for wasm consumers.
- `seren-secrets-resolver` - host-side resolver for `seren-secrets://...` references. It signs resolve requests, calls a configured API endpoint, unwraps the returned envelopes locally, extracts the requested field, and returns plaintext only to the approved caller.
- `seren-secrets-sidecar` - optional binary target from the resolver crate for non-Rust hosts that need a local loopback resolver process.

## Security invariants

- Private keys, account keys, vault keys, and item content keys are client-side material.
- AAD prefixes are protocol commitments and must change only in coordinated protocol updates.
- Wrapped keys and ciphertext bodies are opaque to the server.
- `seren-secrets://...` resolution signs the request before the server returns encrypted envelopes.
- Resolved plaintext should be zeroized or dropped as soon as the approved operation completes.

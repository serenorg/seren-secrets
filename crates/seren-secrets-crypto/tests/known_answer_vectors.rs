//! Known-answer vectors.
//!
//! These tests pin the wire format and algorithm choices that released
//! versions of Seren Secrets must keep byte-compatible. A failure here means
//! a deliberate protocol-version bump, not a routine refactor.
//!
//! The vectors are intentionally redundant with primitive-level unit tests:
//! this file gives reviewers one place to check algorithms, AAD framing, and
//! tag-byte mapping.
//!
//! Coverage:
//! - Protocol version byte (1)
//! - Tag byte values for every Tag variant
//! - Wire-envelope framing: version || tag || payload
//! - AEAD with AAD: XChaCha20-Poly1305 over fixed key + fixed nonce +
//!   fixed AAD + fixed plaintext decrypts via our wrapper.
//! - HMAC-SHA256 blind-index output for a fixed key + title pair.
//! - Ed25519 verify against the RFC 8032 test vector 1.

use seren_secrets_crypto::keys::{
    BlindIndexKey, IdentitySigningKeypair, IdentitySigningPrivateKey, IdentitySigningPublicKey,
};
use seren_secrets_crypto::protocol::blind_index::blind_index_title;
use seren_secrets_crypto::signing::{sign, verify};
use seren_secrets_crypto::wire::{PROTOCOL_VERSION, Tag, decode, decode_expecting, encode};

/// Decode a lowercase hex string into a Vec<u8>. ASCII only; no spaces.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex literal has odd length");
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let high = from_hex_nibble(chunk[0]);
        let low = from_hex_nibble(chunk[1]);
        out.push((high << 4) | low);
    }
    out
}

fn from_hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => 10 + (c - b'a'),
        b'A'..=b'F' => 10 + (c - b'A'),
        _ => panic!("invalid hex nibble: {c:#04x}"),
    }
}

#[test]
fn protocol_version_byte_is_one() {
    // The protocol version byte prefixes every wire blob. Bumping this is
    // a deliberate breaking change; an accidental bump is a vault-corrupting
    // bug, so the constant is pinned here.
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn tag_byte_values_are_pinned() {
    // The Tag enum's u8 representation is part of the wire format. Adding
    // a variant is fine; reordering or repurposing existing values would
    // make older stored blobs decode under the wrong tag.
    assert_eq!(Tag::AeadXChaCha as u8, 0x01);
    assert_eq!(Tag::SealedBox as u8, 0x02);
    assert_eq!(Tag::HmacSha256 as u8, 0x03);
    assert_eq!(Tag::Ed25519Sig as u8, 0x04);
    assert_eq!(Tag::AccountWrap as u8, 0x05);
}

#[test]
fn wire_envelope_layout_is_version_then_tag_then_payload() {
    // The envelope layout that every other primitive's KAT depends on.
    let envelope = encode(Tag::AeadXChaCha, b"hello");
    assert_eq!(envelope, vec![0x01, 0x01, b'h', b'e', b'l', b'l', b'o']);

    // Round-trip via decode_expecting must yield the exact payload.
    let payload = decode_expecting(&envelope, Tag::AeadXChaCha).unwrap();
    assert_eq!(payload, b"hello");

    // decode() (no expectation) must report the tag the producer set.
    let (tag, payload) = decode(&envelope).unwrap();
    assert_eq!(tag, Tag::AeadXChaCha);
    assert_eq!(payload, b"hello");
}

#[test]
fn aead_with_aad_pins_xchacha20_poly1305_and_aad_framing() {
    // KAT for `xchacha20_decrypt_with_aad`. The ciphertext was produced
    // offline by the chacha20poly1305 crate with:
    //   key   = 00 01 02 .. 1f  (32 bytes)
    //   nonce = 20 21 22 .. 37  (24 bytes)
    //   aad   = "body:item-0001"
    //   pt    = "hello world"
    //
    // The wire envelope is version || tag || nonce || ciphertext+tag.
    // Our wrapper must decrypt this exact byte sequence to the original
    // plaintext. A failure here means we changed the AEAD construction
    // (algorithm, nonce framing, or AAD handling) in a way that older
    // vaults can no longer be read.
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };

    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    let mut nonce_bytes = [0u8; 24];
    for (i, b) in nonce_bytes.iter_mut().enumerate() {
        *b = 0x20 + i as u8;
    }
    let aad: &[u8] = b"body:item-0001";
    let plaintext: &[u8] = b"hello world";

    // Build the expected wire blob deterministically from the same inputs.
    // If the algorithm constant in `aead.rs` is ever changed, both sides
    // change in lockstep and the test passes -- but the `seal_with_fixture`
    // assertion below pins the *exact* ciphertext bytes from the
    // chacha20poly1305 1.0 reference, so an algorithm swap (e.g. to
    // AES-256-GCM) would produce different ciphertext under the same
    // inputs and fail loudly here.
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(
            nonce_bytes
                .as_slice()
                .try_into()
                .expect("nonce has fixed length"),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20Poly1305 encrypt with valid inputs cannot fail");

    // Recorded reference ciphertext for the inputs above. If the
    // chacha20poly1305 crate is updated, this assertion is the canary
    // that the upgrade did not change the output bytes.
    // Recorded by running the encrypt step above and capturing the
    // output. If the chacha20poly1305 crate changes its output for the
    // same key/nonce/aad/pt, this assertion is the canary; either pin a
    // new vector deliberately or revert the library bump.
    let expected_ct = hex("753c21a7141763e44ad234e29e8cff547a24961800e5f47a6cef50");
    assert_eq!(
        ct, expected_ct,
        "chacha20poly1305 output drifted; either upgrade pinned vector or revert library bump"
    );

    let mut blob = Vec::with_capacity(2 + nonce_bytes.len() + ct.len());
    blob.push(PROTOCOL_VERSION);
    blob.push(Tag::AeadXChaCha as u8);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);

    // Round-trip through our wrapper.
    let recovered =
        seren_secrets_crypto::aead::xchacha20_decrypt_with_aad(&key, &blob, aad).unwrap();
    assert_eq!(recovered, plaintext);

    // Tampering the AAD must surface AuthFailure (pins encrypt-then-MAC
    // semantics on AAD).
    let err =
        seren_secrets_crypto::aead::xchacha20_decrypt_with_aad(&key, &blob, b"body:item-0002")
            .unwrap_err();
    assert!(matches!(
        err,
        seren_secrets_crypto::CryptoError::AuthFailure
    ));
}

#[test]
fn blind_index_pins_hmac_sha256_under_normalized_title() {
    // KAT for `blind_index_title`. Title normalization is case-fold +
    // trim-whitespace before HMAC-SHA256 under the per-vault key. A drift
    // in normalization or hash choice would silently break the
    // exact-title lookup index across deployments.
    let key = BlindIndexKey::from_bytes([0x42; 32]);
    let blob = blind_index_title(&key, "  Example Login  ");

    // Wire shape: version || tag(HmacSha256) || 32-byte mac.
    assert_eq!(blob[0], PROTOCOL_VERSION);
    assert_eq!(blob[1], Tag::HmacSha256 as u8);
    assert_eq!(blob.len(), 2 + 32);

    // Computed once via `HMAC-SHA256(key=0x42*32, msg="example login")`
    // and pinned here. If a future change reorders normalization steps
    // (e.g. NFC normalization) or alters the MAC algorithm, this
    // assertion must be revisited together with a deliberate index
    // rebuild plan; it is not safe to silently update.
    let expected_mac = hex("aa95dfd1c52128cfdb4f5de5a30c1c269c3c8188f01ff7fab33daebdd642066c");
    assert_eq!(&blob[2..], expected_mac.as_slice());

    // Idempotence vs whitespace and case is what the normalization is
    // meant to provide -- if it ever stops being idempotent, the index
    // lookup misses items the user can see.
    let blob2 = blind_index_title(&key, "EXAMPLE LOGIN");
    assert_eq!(blob, blob2);
}

#[test]
fn ed25519_verify_matches_rfc_8032_test_vector_1() {
    // RFC 8032 section 7.1 test vector 1:
    //   secret key  9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    //   public key  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
    //   message     (empty)
    //   signature   e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
    //
    // Pins the choice of signing algorithm (Ed25519, not ECDSA, not
    // Ed448) and the canonical 64-byte signature framing.
    let sk_bytes = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk_bytes = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signing_private = IdentitySigningPrivateKey::from_slice(&sk_bytes).unwrap();
    let signing_public = IdentitySigningPublicKey::from_slice(&pk_bytes).unwrap();

    // Public key derives correctly from the private key.
    let kp = IdentitySigningKeypair::from_private(signing_private.clone());
    assert_eq!(kp.public, signing_public);

    // Our sign over an empty message produces an Ed25519Sig-tagged
    // envelope whose payload matches the RFC's expected signature bytes.
    let sig_blob = sign(&signing_private, b"");
    assert_eq!(sig_blob[0], PROTOCOL_VERSION);
    assert_eq!(sig_blob[1], Tag::Ed25519Sig as u8);
    assert_eq!(sig_blob.len(), 2 + 64);

    let expected_sig = hex(concat!(
        "e5564300c360ac729086e2cc806e828a",
        "84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46b",
        "d25bf5f0595bbe24655141438e7a100b",
    ));
    assert_eq!(&sig_blob[2..], expected_sig.as_slice());

    // Verify accepts the RFC signature.
    verify(&signing_public, b"", &sig_blob).unwrap();

    // Tampering any byte of the signature payload must surface
    // InvalidSignature, not a silent accept.
    let mut tampered = sig_blob.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = verify(&signing_public, b"", &tampered).unwrap_err();
    assert!(matches!(
        err,
        seren_secrets_crypto::CryptoError::InvalidSignature
    ));
}

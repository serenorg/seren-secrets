//! Property tests for the crypto primitives.
//!
//! These complement the hand-written unit tests and the known-answer
//! vectors. The point of property tests is to catch edge cases that a
//! human did not think to enumerate: empty plaintexts, single-byte
//! plaintexts, ciphertext bit-flips at arbitrary offsets, weird
//! whitespace in blind-index inputs, and so on. Each property is stated
//! as an invariant that must hold for every input the generator
//! produces.
//!
//! The proptest case count is kept modest so CI runs stay fast; the
//! tests primarily document the invariants and shrink toward minimal
//! failing inputs when something regresses.

use proptest::prelude::*;
use seren_secrets_crypto::CryptoError;
use seren_secrets_crypto::aead::{
    xchacha20_decrypt, xchacha20_decrypt_with_aad, xchacha20_encrypt, xchacha20_encrypt_with_aad,
};
use seren_secrets_crypto::kem::{seal, unseal};
use seren_secrets_crypto::keys::{
    BlindIndexKey, IdentityKemKeypair, IdentityKemPrivateKey, IdentitySigningKeypair,
    IdentitySigningPrivateKey,
};
use seren_secrets_crypto::protocol::blind_index::blind_index_title;
use seren_secrets_crypto::signing::{sign, verify};
use seren_secrets_crypto::wire::{Tag, decode, decode_expecting, encode};

fn tag_strategy() -> impl Strategy<Value = Tag> {
    prop_oneof![
        Just(Tag::AeadXChaCha),
        Just(Tag::SealedBox),
        Just(Tag::HmacSha256),
        Just(Tag::Ed25519Sig),
        Just(Tag::AccountWrap),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any payload, any tag, encodes and round-trips through decode.
    #[test]
    fn wire_envelope_round_trips(
        tag in tag_strategy(),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let blob = encode(tag, &payload);
        let (decoded_tag, decoded_payload) = decode(&blob).expect("encode produces valid wire blob");
        prop_assert_eq!(decoded_tag, tag);
        prop_assert_eq!(decoded_payload, payload.as_slice());

        let bound_payload = decode_expecting(&blob, tag).expect("expected tag matches");
        prop_assert_eq!(bound_payload, payload.as_slice());
    }

    /// AEAD round-trip for any 32-byte key and any plaintext.
    #[test]
    fn aead_round_trip(
        key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let blob = xchacha20_encrypt(&key, &plaintext);
        let recovered = xchacha20_decrypt(&key, &blob).expect("round-trip decrypt");
        prop_assert_eq!(recovered, plaintext);
    }

    /// AEAD with AAD round-trips for any key, plaintext, and AAD.
    #[test]
    fn aead_with_aad_round_trip(
        key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        aad in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let blob = xchacha20_encrypt_with_aad(&key, &plaintext, &aad);
        let recovered = xchacha20_decrypt_with_aad(&key, &blob, &aad)
            .expect("round-trip decrypt with same aad");
        prop_assert_eq!(recovered, plaintext);
    }

    /// Bit-flipping any single byte after the wire header invalidates
    /// the AEAD tag. The first two bytes are version || tag which would
    /// surface as MalformedWire rather than AuthFailure, so the
    /// generator skips them.
    #[test]
    fn aead_tamper_rejects(
        key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 16..256),
        flip_byte in any::<u8>(),
    ) {
        let blob = xchacha20_encrypt(&key, &plaintext);
        prop_assume!(blob.len() > 2);
        let body_len = blob.len() - 2;
        let offset = 2 + (flip_byte as usize % body_len);
        let mut tampered = blob.clone();
        tampered[offset] ^= 0x01;
        let err = xchacha20_decrypt(&key, &tampered).unwrap_err();
        prop_assert!(matches!(err, CryptoError::AuthFailure | CryptoError::InvalidCiphertext));
    }

    /// AAD context separation: a ciphertext sealed under aad A cannot
    /// decrypt under aad B for any choice of differing inputs.
    #[test]
    fn aead_different_aad_fails(
        key in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..128),
        aad_a in proptest::collection::vec(any::<u8>(), 1..64),
        aad_b in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(aad_a != aad_b);
        let blob = xchacha20_encrypt_with_aad(&key, &plaintext, &aad_a);
        let err = xchacha20_decrypt_with_aad(&key, &blob, &aad_b).unwrap_err();
        prop_assert!(matches!(err, CryptoError::AuthFailure));
    }

    /// X25519 sealed-box round-trip with any 32-byte recipient secret
    /// and any plaintext. We derive the public key from the private to
    /// avoid generating an invalid keypair.
    #[test]
    fn kem_round_trip(
        sk_bytes in any::<[u8; 32]>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let private = IdentityKemPrivateKey::from_bytes(sk_bytes);
        let keypair = IdentityKemKeypair::from_private(private.clone());
        let blob = seal(&keypair.public, &plaintext);
        let recovered = unseal(&private, &blob).expect("kem round-trip");
        prop_assert_eq!(recovered, plaintext);
    }

    /// Ed25519 sign and verify is total for any message under any
    /// well-formed signing private key (ed25519-dalek treats any 32 random
    /// bytes as a valid signing seed).
    #[test]
    fn ed25519_sign_verify_round_trip(
        sk_bytes in any::<[u8; 32]>(),
        message in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let private = IdentitySigningPrivateKey::from_bytes(sk_bytes);
        let keypair = IdentitySigningKeypair::from_private(private.clone());
        let signature = sign(&private, &message);
        verify(&keypair.public, &message, &signature).expect("verify accepts own signature");
    }

    /// Ed25519 verify with a different verifying key always rejects. The
    /// generator picks two distinct seeds; the property is total over any
    /// such pair.
    #[test]
    fn ed25519_verify_with_wrong_key_rejects(
        sk_a in any::<[u8; 32]>(),
        sk_b in any::<[u8; 32]>(),
        message in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        prop_assume!(sk_a != sk_b);
        let private_a = IdentitySigningPrivateKey::from_bytes(sk_a);
        let private_b = IdentitySigningPrivateKey::from_bytes(sk_b);
        let kp_b = IdentitySigningKeypair::from_private(private_b);
        let signature = sign(&private_a, &message);
        let err = verify(&kp_b.public, &message, &signature).unwrap_err();
        prop_assert!(matches!(err, CryptoError::InvalidSignature));
    }

    /// Blind index is invariant to leading/trailing whitespace and to
    /// case in the input title. The implementation case-folds and trims;
    /// any input that differs only by whitespace edges or letter case
    /// must produce the same MAC under the same key.
    #[test]
    fn blind_index_is_normalized(
        key in any::<[u8; 32]>(),
        title in "[a-zA-Z0-9 ]{1,32}",
        leading_ws in "[ \t]{0,4}",
        trailing_ws in "[ \t]{0,4}",
    ) {
        let key = BlindIndexKey::from_bytes(key);
        let canonical = blind_index_title(&key, title.trim());
        let with_ws = blind_index_title(&key, &format!("{leading_ws}{title}{trailing_ws}"));
        let lowered = blind_index_title(&key, &title.to_lowercase());
        let uppered = blind_index_title(&key, &title.to_uppercase());
        prop_assert_eq!(&canonical, &with_ws);
        prop_assert_eq!(&canonical, &lowered);
        prop_assert_eq!(&canonical, &uppered);
    }

    /// Different titles under the same key produce different MACs with
    /// overwhelming probability. The HMAC-SHA256 output space is
    /// 2^256, so collisions are astronomically unlikely; the property
    /// holds for all distinct inputs.
    #[test]
    fn blind_index_diverges_for_distinct_titles(
        key in any::<[u8; 32]>(),
        title_a in "[a-z]{1,16}",
        title_b in "[a-z]{1,16}",
    ) {
        prop_assume!(title_a.trim() != title_b.trim());
        let key = BlindIndexKey::from_bytes(key);
        let a = blind_index_title(&key, &title_a);
        let b = blind_index_title(&key, &title_b);
        prop_assert_ne!(a, b);
    }
}

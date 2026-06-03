//! X25519 sealed-box wrap/unwrap for content keys.
//!
//! Format on the wire: `version(1) || tag(SealedBox) || ephemeral_pubkey(32) || ciphertext+tag`.
//! The recipient derives the shared secret with their X25519 private key and
//! the embedded ephemeral public key.
//!
//! Sealed boxes are unauthenticated: any holder of the recipient public key can
//! produce one. Trusted key handoff must be authenticated above this module.
//!
//! `unseal` rejects non-contributory ephemeral public keys before deriving the
//! box key.

use crypto_box::{PublicKey, SecretKey, aead::Aead};
use rand_core::OsRng;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{IdentityKemPrivateKey, IdentityKemPublicKey};
use crate::wire::{Tag, decode_expecting, encode};

const EPHEMERAL_PUBLIC_LEN: usize = 32;

/// Wrap (encrypt) `plaintext` so that only the holder of the private key
/// matching `recipient` can decrypt it.
///
/// Sealed boxes carry no AAD. Callers must bind context outside this blob
/// before using it for content-key handoff.
pub fn seal(recipient: &IdentityKemPublicKey, plaintext: &[u8]) -> Vec<u8> {
    let recipient_pk = PublicKey::from(*recipient.as_bytes());
    let ephemeral_sk = SecretKey::generate(&mut OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    let salsa_box = crypto_box::SalsaBox::new(&recipient_pk, &ephemeral_sk);
    // Nonce derived from blake2b(ephemeral_pk || recipient_pk) per libsodium sealed-box spec.
    let nonce = sealed_box_nonce(&ephemeral_pk, &recipient_pk);
    let ct = salsa_box
        .encrypt(&nonce.into(), plaintext)
        .expect("crypto_box encrypt cannot fail with a valid keypair");

    let mut payload = Vec::with_capacity(EPHEMERAL_PUBLIC_LEN + ct.len());
    payload.extend_from_slice(ephemeral_pk.as_bytes());
    payload.extend_from_slice(&ct);
    encode(Tag::SealedBox, &payload)
}

/// Unwrap a payload produced by [`seal`] using the recipient's private key.
///
/// The recipient's public key is derived from the private key inside this
/// function so callers cannot accidentally pass a mismatched public key.
pub fn unseal(private: &IdentityKemPrivateKey, blob: &[u8]) -> CryptoResult<Vec<u8>> {
    let payload = decode_expecting(blob, Tag::SealedBox)?;
    if payload.len() < EPHEMERAL_PUBLIC_LEN + 16 {
        return Err(CryptoError::InvalidCiphertext);
    }
    let mut ephemeral = [0u8; EPHEMERAL_PUBLIC_LEN];
    ephemeral.copy_from_slice(&payload[..EPHEMERAL_PUBLIC_LEN]);

    // Non-contributory points make the box key independent of the recipient.
    let recipient_secret = x25519_dalek::StaticSecret::from(*private.as_bytes());
    if !recipient_secret
        .diffie_hellman(&x25519_dalek::PublicKey::from(ephemeral))
        .was_contributory()
    {
        return Err(CryptoError::InvalidKey("low-order ephemeral public key"));
    }

    let ephemeral_pk = PublicKey::from(ephemeral);
    let recipient_sk = SecretKey::from(*private.as_bytes());
    let recipient_pk = recipient_sk.public_key();
    let salsa_box = crypto_box::SalsaBox::new(&ephemeral_pk, &recipient_sk);
    let nonce = sealed_box_nonce(&ephemeral_pk, &recipient_pk);

    salsa_box
        .decrypt(&nonce.into(), &payload[EPHEMERAL_PUBLIC_LEN..])
        .map_err(|_| CryptoError::AuthFailure)
}

/// libsodium sealed-box nonce: blake2b-24(ephemeral_pk || recipient_pk).
fn sealed_box_nonce(ephemeral_pk: &PublicKey, recipient_pk: &PublicKey) -> [u8; 24] {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    let mut h = Blake2bVar::new(24).expect("24-byte blake2b output");
    h.update(ephemeral_pk.as_bytes());
    h.update(recipient_pk.as_bytes());
    let mut nonce = [0u8; 24];
    h.finalize_variable(&mut nonce)
        .expect("24-byte output buffer");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKemKeypair;

    #[test]
    fn round_trip() {
        let kp = IdentityKemKeypair::generate();
        let pt = b"some content key";
        let blob = seal(&kp.public, pt);
        let recovered = unseal(&kp.private, &blob).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_recipient_fails() {
        let kp1 = IdentityKemKeypair::generate();
        let kp2 = IdentityKemKeypair::generate();
        let blob = seal(&kp1.public, b"x");
        let err = unseal(&kp2.private, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn tamper_fails() {
        let kp = IdentityKemKeypair::generate();
        let mut blob = seal(&kp.public, b"x");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err = unseal(&kp.private, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn unique_ephemerals() {
        let kp = IdentityKemKeypair::generate();
        let a = seal(&kp.public, b"x");
        let b = seal(&kp.public, b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_low_order_ephemeral_public_key() {
        let kp = IdentityKemKeypair::generate();
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; EPHEMERAL_PUBLIC_LEN]);
        payload.extend_from_slice(&[0u8; 16]);
        let blob = encode(Tag::SealedBox, &payload);
        let err = unseal(&kp.private, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidKey(_)));
    }

    #[test]
    fn tampered_ephemeral_pubkey_fails() {
        let kp = IdentityKemKeypair::generate();
        let mut blob = seal(&kp.public, b"payload");
        // Bytes 0,1 are version+tag; ephemeral pubkey starts at byte 2.
        blob[2] ^= 0x80;
        let err = unseal(&kp.private, &blob).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn nonce_matches_libsodium_blake2b24() {
        // Known-answer vector: blake2b-24(ephemeral_pk || recipient_pk) must
        // match libsodium's crypto_box_seal_nonce derivation. Cross-checked
        // against pynacl's nacl.hash.blake2b with digest_size=24.
        let ephemeral = crypto_box::PublicKey::from([1u8; 32]);
        let recipient = crypto_box::PublicKey::from([2u8; 32]);
        let nonce = sealed_box_nonce(&ephemeral, &recipient);
        let expected = [
            0x02, 0x7c, 0x5e, 0x23, 0x8e, 0xb7, 0x20, 0x85, 0x27, 0x60, 0xb5, 0x96, 0xd6, 0xb4,
            0x70, 0xd4, 0x14, 0x5a, 0x35, 0x8c, 0x76, 0x29, 0xbf, 0x25,
        ];
        assert_eq!(nonce, expected);
    }

    #[test]
    fn unseals_libsodium_produced_ciphertext() {
        // Cross-implementation vector: a sealed box produced by libsodium
        // (via pynacl) for recipient secret key bytes 0x00..0x1f, plaintext
        // "hello world". Our unseal must decrypt it.
        let mut sk_bytes = [0u8; 32];
        for (i, b) in sk_bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let private = crate::keys::IdentityKemPrivateKey::from_bytes(sk_bytes);
        let sealed_hex = "a34224acc7ed18666226e31f852919819c89cf69b1d6d34b4c4211fb04e7bc3c58eee79d8af7235f69fccbaf84cd4c242b63b0ce39f93383e925f0";
        let mut sealed = Vec::with_capacity(2 + sealed_hex.len() / 2);
        sealed.push(crate::wire::PROTOCOL_VERSION);
        sealed.push(Tag::SealedBox as u8);
        for chunk in sealed_hex.as_bytes().chunks(2) {
            let s = std::str::from_utf8(chunk).unwrap();
            sealed.push(u8::from_str_radix(s, 16).unwrap());
        }
        let pt = unseal(&private, &sealed).unwrap();
        assert_eq!(&pt, b"hello world");
    }
}

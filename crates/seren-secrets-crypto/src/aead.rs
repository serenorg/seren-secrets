//! XChaCha20-Poly1305 envelope encryption helpers.
//!
//! Every ciphertext produced here is a versioned blob:
//! `version(1) || tag(AeadXChaCha) || nonce(24) || ciphertext || tag(16)`.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};

use crate::error::{CryptoError, CryptoResult};
use crate::wire::{Tag, decode_expecting, encode};

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Encrypt `plaintext` under `key` with random nonce, returning a versioned
/// XChaCha20-Poly1305 envelope.
pub fn xchacha20_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .expect("XChaCha20-Poly1305 encrypt cannot fail with a valid key and nonce");
    let mut payload = Vec::with_capacity(NONCE_LEN + ct.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ct);
    encode(Tag::AeadXChaCha, &payload)
}

/// Encrypt `plaintext` with the given `key` and additional authenticated data.
pub fn xchacha20_encrypt_with_aad(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::Payload;
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encrypt cannot fail with a valid key and nonce");
    let mut payload = Vec::with_capacity(NONCE_LEN + ct.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ct);
    encode(Tag::AeadXChaCha, &payload)
}

/// Decrypt a blob produced by [`xchacha20_encrypt`].
pub fn xchacha20_decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> CryptoResult<Vec<u8>> {
    let payload = decode_expecting(blob, Tag::AeadXChaCha)?;
    if payload.len() < NONCE_LEN + 16 {
        return Err(CryptoError::InvalidCiphertext);
    }
    let nonce = XNonce::from_slice(&payload[..NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce, &payload[NONCE_LEN..])
        .map_err(|_| CryptoError::AuthFailure)
}

/// Decrypt a blob produced by [`xchacha20_encrypt_with_aad`].
pub fn xchacha20_decrypt_with_aad(
    key: &[u8; KEY_LEN],
    blob: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    let payload = decode_expecting(blob, Tag::AeadXChaCha)?;
    if payload.len() < NONCE_LEN + 16 {
        return Err(CryptoError::InvalidCiphertext);
    }
    let nonce = XNonce::from_slice(&payload[..NONCE_LEN]);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &payload[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_no_aad() {
        let key = [7u8; 32];
        let pt = b"important data";
        let ct = xchacha20_encrypt(&key, pt);
        assert_ne!(&ct[2..], pt);
        let recovered = xchacha20_decrypt(&key, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn round_trip_with_aad() {
        let key = [9u8; 32];
        let pt = b"data";
        let aad = b"contextual binding";
        let ct = xchacha20_encrypt_with_aad(&key, pt, aad);
        let recovered = xchacha20_decrypt_with_aad(&key, &ct, aad).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [9u8; 32];
        let ct = xchacha20_encrypt_with_aad(&key, b"data", b"context-a");
        let err = xchacha20_decrypt_with_aad(&key, &ct, b"context-b").unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn tamper_fails() {
        let key = [3u8; 32];
        let mut ct = xchacha20_encrypt(&key, b"secret");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let err = xchacha20_decrypt(&key, &ct).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let ct = xchacha20_encrypt(&key1, b"x");
        let err = xchacha20_decrypt(&key2, &ct).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn unique_nonces() {
        let key = [4u8; 32];
        let a = xchacha20_encrypt(&key, b"same");
        let b = xchacha20_encrypt(&key, b"same");
        assert_ne!(a, b);
    }

    #[test]
    fn short_blob_rejected() {
        let key = [0u8; 32];
        let err = xchacha20_decrypt(&key, &[1, 1, 0, 0]).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidCiphertext));
    }
}

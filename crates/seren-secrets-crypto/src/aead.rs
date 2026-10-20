//! XChaCha20-Poly1305 envelope encryption helpers.
//!
//! Every ciphertext produced here is a versioned blob:
//! `version(1) || tag(AeadXChaCha) || nonce(24) || ciphertext || tag(16)`.

use crate::entropy::fill_random;
use crate::error::{CryptoError, CryptoResult};
use crate::wire::{Tag, decode_expecting, encode_with_capacity};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadInOut, KeyInit},
};

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Encrypt `plaintext` under `key` with random nonce, returning a versioned
/// XChaCha20-Poly1305 envelope.
pub fn xchacha20_encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    xchacha20_encrypt_with_aad(key, plaintext, b"")
}

/// Encrypt `plaintext` with the given `key` and additional authenticated data.
pub fn xchacha20_encrypt_with_aad(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes);
    let nonce: &XNonce = nonce_bytes
        .as_slice()
        .try_into()
        .expect("nonce has fixed length");
    // Reserve the complete wire envelope before copying plaintext, then seal
    // only the message suffix. The prefix and nonce are not part of the body.
    let mut envelope = zeroize::Zeroizing::new(encode_with_capacity(
        Tag::AeadXChaCha,
        &nonce_bytes,
        plaintext.len() + 16,
    ));
    let message_start = envelope.len();
    envelope.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_inout_detached(nonce, aad, (&mut envelope[message_start..]).into())
        .expect("XChaCha20-Poly1305 encrypt cannot fail with a valid key and nonce");
    envelope.extend_from_slice(&tag);
    std::mem::take(&mut *envelope)
}

/// Decrypt a blob produced by [`xchacha20_encrypt`].
pub fn xchacha20_decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> CryptoResult<Vec<u8>> {
    let payload = decode_expecting(blob, Tag::AeadXChaCha)?;
    if payload.len() < NONCE_LEN + 16 {
        return Err(CryptoError::InvalidCiphertext);
    }
    let nonce: &XNonce = payload[..NONCE_LEN]
        .try_into()
        .expect("nonce length was validated");
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
    let nonce: &XNonce = payload[..NONCE_LEN]
        .try_into()
        .expect("nonce length was validated");
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
    fn encryption_matches_the_wire_layout() {
        use chacha20poly1305::aead::Payload;

        let key = [11u8; 32];
        let cipher = XChaCha20Poly1305::new((&key).into());
        for plaintext in [b"".as_slice(), b"binary\0message\xff".as_slice()] {
            for aad in [b"".as_slice(), b"context".as_slice()] {
                let envelope = xchacha20_encrypt_with_aad(&key, plaintext, aad);
                let payload = decode_expecting(&envelope, Tag::AeadXChaCha).unwrap();
                assert_eq!(envelope.len(), 2 + NONCE_LEN + plaintext.len() + 16);
                let nonce: &XNonce = payload[..NONCE_LEN].try_into().unwrap();
                let expected = cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: plaintext,
                            aad,
                        },
                    )
                    .unwrap();
                assert_eq!(&payload[NONCE_LEN..], expected);
                assert_eq!(
                    xchacha20_decrypt_with_aad(&key, &envelope, aad).unwrap(),
                    plaintext
                );
            }
        }
    }

    #[test]
    fn empty_plaintext_round_trips_without_aad() {
        let key = [12u8; 32];
        let envelope = xchacha20_encrypt(&key, b"");
        assert_eq!(envelope.len(), 2 + NONCE_LEN + 16);
        assert!(xchacha20_decrypt(&key, &envelope).unwrap().is_empty());
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

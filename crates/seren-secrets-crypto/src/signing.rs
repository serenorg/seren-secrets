//! Ed25519 sign / verify.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::wire::{Tag, decode_expecting, encode};

const SIGNATURE_BYTES: usize = 64;

pub fn sign(private: &IdentitySigningPrivateKey, message: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(private.as_bytes());
    let sig = signing.sign(message);
    encode(Tag::Ed25519Sig, &sig.to_bytes())
}

pub fn verify(public: &IdentitySigningPublicKey, message: &[u8], blob: &[u8]) -> CryptoResult<()> {
    let payload = decode_expecting(blob, Tag::Ed25519Sig)?;
    if payload.len() != SIGNATURE_BYTES {
        return Err(CryptoError::MalformedWire("ed25519 signature wrong length"));
    }
    let mut sig_bytes = [0u8; SIGNATURE_BYTES];
    sig_bytes.copy_from_slice(payload);
    let sig = Signature::from_bytes(&sig_bytes);
    let verifying = VerifyingKey::from_bytes(public.as_bytes())
        .map_err(|_| CryptoError::InvalidKey("ed25519 verifying key"))?;
    // verify_strict rejects small-order/non-canonical components for
    // malleability resistance, beyond the per-message id/challenge binding.
    verifying
        .verify_strict(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentitySigningKeypair;

    #[test]
    fn round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let msg = b"vault grant: alice -> agent-foo";
        let sig = sign(&kp.private, msg);
        verify(&kp.public, msg, &sig).unwrap();
    }

    #[test]
    fn wrong_signer_fails() {
        let kp1 = IdentitySigningKeypair::generate();
        let kp2 = IdentitySigningKeypair::generate();
        let sig = sign(&kp1.private, b"x");
        let err = verify(&kp2.public, b"x", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = IdentitySigningKeypair::generate();
        let sig = sign(&kp.private, b"original");
        let err = verify(&kp.public, b"tampered", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }
}

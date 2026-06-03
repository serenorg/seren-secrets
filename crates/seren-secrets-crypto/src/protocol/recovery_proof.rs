//! Canonical form for the recovery-completion proof.
//!
//! After the server issues a recovery challenge, the client uses the user's
//! recovery key to unwrap the account key, derives the account signing key,
//! and signs the canonical bytes below. The signature is verified server-side
//! against the user's existing identity signing public key, proving the
//! client genuinely held the recovery key without ever sending it.

use uuid::Uuid;

use crate::error::CryptoResult;
use crate::keys::{IdentityKemPublicKey, IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::signing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProof {
    pub recovery_request_id: Uuid,
    pub user_id: Uuid,
    /// The 32-byte challenge the server issued.
    pub challenge: [u8; 32],
    /// The new account KEM public key the client is about to upload.
    /// Binding it into the proof prevents a captured signature from being
    /// replayed with a different new public key.
    pub new_kem_public_key: IdentityKemPublicKey,
}

fn canonical(proof: &RecoveryProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(b"seren-secrets-recovery-proof\n");
    out.extend_from_slice(b"recovery_request_id=");
    out.extend_from_slice(proof.recovery_request_id.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"user_id=");
    out.extend_from_slice(proof.user_id.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"challenge=");
    out.extend_from_slice(&proof.challenge);
    out.push(b'\n');
    out.extend_from_slice(b"new_kem_public_key=");
    out.extend_from_slice(proof.new_kem_public_key.as_bytes());
    out.push(b'\n');
    out
}

pub fn build_recovery_proof(private: &IdentitySigningPrivateKey, proof: &RecoveryProof) -> Vec<u8> {
    signing::sign(private, &canonical(proof))
}

pub fn verify_recovery_proof(
    public: &IdentitySigningPublicKey,
    proof: &RecoveryProof,
    signature: &[u8],
) -> CryptoResult<()> {
    signing::verify(public, &canonical(proof), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKemKeypair, IdentitySigningKeypair};

    fn sample(challenge: [u8; 32], new_pk: IdentityKemPublicKey) -> RecoveryProof {
        RecoveryProof {
            recovery_request_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            challenge,
            new_kem_public_key: new_pk,
        }
    }

    #[test]
    fn round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let new = IdentityKemKeypair::generate();
        let proof = sample([7u8; 32], new.public);
        let sig = build_recovery_proof(&kp.private, &proof);
        verify_recovery_proof(&kp.public, &proof, &sig).unwrap();
    }

    #[test]
    fn wrong_signer_fails() {
        let kp1 = IdentitySigningKeypair::generate();
        let kp2 = IdentitySigningKeypair::generate();
        let new = IdentityKemKeypair::generate();
        let proof = sample([1u8; 32], new.public);
        let sig = build_recovery_proof(&kp1.private, &proof);
        let err = verify_recovery_proof(&kp2.public, &proof, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_challenge_fails() {
        let kp = IdentitySigningKeypair::generate();
        let new = IdentityKemKeypair::generate();
        let proof = sample([2u8; 32], new.public);
        let sig = build_recovery_proof(&kp.private, &proof);
        let mut tampered = proof.clone();
        tampered.challenge[0] ^= 0x80;
        let err = verify_recovery_proof(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_new_pubkey_fails() {
        let kp = IdentitySigningKeypair::generate();
        let new = IdentityKemKeypair::generate();
        let other = IdentityKemKeypair::generate();
        let proof = sample([3u8; 32], new.public);
        let sig = build_recovery_proof(&kp.private, &proof);
        let mut tampered = proof.clone();
        tampered.new_kem_public_key = other.public;
        let err = verify_recovery_proof(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }
}

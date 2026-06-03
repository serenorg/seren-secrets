//! Signed proof for account-secrets replacement.
//!
//! The proof binds the user, timestamp, and replacement blob digest to the
//! existing account signing key.

use jiff::{SignedDuration, Timestamp};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::signing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSecretsUpdateProof {
    pub user_id: Uuid,
    pub issued_at: Timestamp,
    /// SHA-256 over the canonical encoding of the new blob; see
    /// [`digest_account_secrets_blob`].
    pub blob_digest: [u8; 32],
}

/// Hash the replacement account-secrets blob into a 32-byte digest.
///
/// Fields are length-prefixed so raw wrap bytes cannot blur field boundaries.
pub fn digest_account_secrets_blob(
    kdf_params_json: &[u8],
    recovery_kdf_params_json: &[u8],
    account_key_wrap: &[u8],
    account_kem_private_wrap: &[u8],
    account_signing_private_wrap: &[u8],
    recovery_key_wrap: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"seren-account-secrets-blob\x00");
    let fields: [(&[u8], &[u8]); 6] = [
        (b"kdf_params", kdf_params_json),
        (b"recovery_kdf_params", recovery_kdf_params_json),
        (b"account_key_wrap", account_key_wrap),
        (b"account_kem_private_wrap", account_kem_private_wrap),
        (
            b"account_signing_private_wrap",
            account_signing_private_wrap,
        ),
        (b"recovery_key_wrap", recovery_key_wrap),
    ];
    for (label, value) in fields {
        h.update((label.len() as u64).to_be_bytes());
        h.update(label);
        h.update((value.len() as u64).to_be_bytes());
        h.update(value);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Serialize JSON with recursively-sorted object keys for proof digests.
///
/// Both sides of the proof (the client computing the digest to sign and the
/// server recomputing it to verify) must feed the KDF fields through this same
/// function so the digests match byte-for-byte. Non-integer numbers are
/// rejected because they have no single canonical textual form.
pub fn canonical_json_bytes(value: &Value) -> CryptoResult<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical_json_value(value, &mut out)?;
    Ok(out)
}

fn write_canonical_json_value(value: &Value, out: &mut Vec<u8>) -> CryptoResult<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.is_f64() {
                return Err(CryptoError::Canonicalization("non-integer json number"));
            }
            out.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => {
            serde_json::to_writer(&mut *out, string)
                .map_err(|_| CryptoError::Canonicalization("json string"))?;
        }
        Value::Array(values) => {
            out.push(b'[');
            for (idx, item) in values.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            for (idx, (key, item)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)
                    .map_err(|_| CryptoError::Canonicalization("json object key"))?;
                out.push(b':');
                write_canonical_json_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn canonical(proof: &AccountSecretsUpdateProof) -> Vec<u8> {
    let ts = proof.issued_at.to_string();
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"seren-secrets-account-secrets-update\n");
    out.extend_from_slice(b"user_id=");
    out.extend_from_slice(proof.user_id.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"issued_at=");
    out.extend_from_slice(ts.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(b"blob_digest=");
    out.extend_from_slice(&proof.blob_digest);
    out.push(b'\n');
    out
}

pub fn build_update_proof(
    private: &IdentitySigningPrivateKey,
    proof: &AccountSecretsUpdateProof,
) -> Vec<u8> {
    signing::sign(private, &canonical(proof))
}

/// Verify the proof signature only. This does not check `issued_at`, so a
/// captured proof stays valid indefinitely. Server callers that replace the
/// stored blob should prefer [`verify_update_proof_fresh`], which also bounds
/// the proof age; use this variant only when freshness is enforced separately.
pub fn verify_update_proof(
    public: &IdentitySigningPublicKey,
    proof: &AccountSecretsUpdateProof,
    signature: &[u8],
) -> CryptoResult<()> {
    signing::verify(public, &canonical(proof), signature)
}

/// Verify the signature and require `issued_at` to be within `max_age`.
pub fn verify_update_proof_fresh(
    public: &IdentitySigningPublicKey,
    proof: &AccountSecretsUpdateProof,
    signature: &[u8],
    now: Timestamp,
    max_age: SignedDuration,
) -> CryptoResult<()> {
    verify_update_proof(public, proof, signature)?;

    if max_age < SignedDuration::ZERO || proof.issued_at > now {
        return Err(CryptoError::InvalidSignature);
    }
    let expires_at = proof
        .issued_at
        .checked_add(max_age)
        .map_err(|_| CryptoError::InvalidSignature)?;
    if expires_at < now {
        return Err(CryptoError::InvalidSignature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentitySigningKeypair;

    fn sample(user: Uuid, digest: [u8; 32]) -> AccountSecretsUpdateProof {
        AccountSecretsUpdateProof {
            user_id: user,
            issued_at: Timestamp::from_second(1_700_000_000).unwrap(),
            blob_digest: digest,
        }
    }

    #[test]
    fn round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [7u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        verify_update_proof(&kp.public, &proof, &sig).unwrap();
    }

    #[test]
    fn wrong_signer_fails() {
        let kp1 = IdentitySigningKeypair::generate();
        let kp2 = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [1u8; 32]);
        let sig = build_update_proof(&kp1.private, &proof);
        let err = verify_update_proof(&kp2.public, &proof, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_digest_fails() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [2u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        let mut tampered = proof.clone();
        tampered.blob_digest[0] ^= 0x80;
        let err = verify_update_proof(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_user_fails() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [3u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        let mut tampered = proof.clone();
        tampered.user_id = Uuid::new_v4();
        let err = verify_update_proof(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_issued_at_fails() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [4u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        let mut tampered = proof.clone();
        tampered.issued_at = Timestamp::from_second(1_700_000_001).unwrap();
        let err = verify_update_proof(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn freshness_window_accepts_current_proof() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [5u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        let now = proof
            .issued_at
            .checked_add(SignedDuration::from_secs(30))
            .unwrap();
        verify_update_proof_fresh(&kp.public, &proof, &sig, now, SignedDuration::from_secs(60))
            .unwrap();
    }

    #[test]
    fn freshness_window_rejects_old_proof() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [6u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        let now = proof
            .issued_at
            .checked_add(SignedDuration::from_secs(61))
            .unwrap();
        let err =
            verify_update_proof_fresh(&kp.public, &proof, &sig, now, SignedDuration::from_secs(60))
                .unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn freshness_window_rejects_future_proof() {
        let kp = IdentitySigningKeypair::generate();
        let proof = sample(Uuid::new_v4(), [7u8; 32]);
        let sig = build_update_proof(&kp.private, &proof);
        let now = proof
            .issued_at
            .checked_sub(SignedDuration::from_secs(1))
            .unwrap();
        let err =
            verify_update_proof_fresh(&kp.public, &proof, &sig, now, SignedDuration::from_secs(60))
                .unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn digest_is_stable_and_sensitive() {
        let d1 = digest_account_secrets_blob(b"a", b"b", b"c", b"d", b"e", b"f");
        let d2 = digest_account_secrets_blob(b"a", b"b", b"c", b"d", b"e", b"f");
        assert_eq!(d1, d2, "digest must be deterministic");
        let d3 = digest_account_secrets_blob(b"a", b"b", b"c", b"d", b"e", b"f-changed");
        assert_ne!(d1, d3, "digest must change when any field changes");
    }

    #[test]
    fn digest_distinguishes_field_boundaries() {
        let d1 = digest_account_secrets_blob(b"ab", b"c", b"d", b"e", b"f", b"g");
        let d2 = digest_account_secrets_blob(b"a", b"bc", b"d", b"e", b"f", b"g");
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_resists_label_smuggling_in_wrap_bytes() {
        let smuggled_kem = b"\naccount_signing_private_wrap=";
        let smuggled =
            digest_account_secrets_blob(b"k", b"r", b"akw", smuggled_kem, b"asw", b"rkw");
        let honest = digest_account_secrets_blob(b"k", b"r", b"akw", b"akem", b"asw", b"rkw");
        assert_ne!(smuggled, honest);

        let a = digest_account_secrets_blob(
            b"k",
            b"r",
            b"akw",
            b"X\naccount_signing_private_wrap=Y",
            b"Z",
            b"rkw",
        );
        let b = digest_account_secrets_blob(
            b"k",
            b"r",
            b"akw",
            b"X",
            b"Y\naccount_signing_private_wrap=Z",
            b"rkw",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn digest_known_answer_vector() {
        // Cross-implementation anchor for KDF JSON and digest framing.
        use crate::kdf::{KdfAlgorithm, KdfParams};
        let kdf = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 65536,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: (0u8..16).collect(),
        };
        let recovery_kdf = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19456,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: (16u8..32).collect(),
        };
        let kdf_bytes = canonical_json_bytes(&serde_json::to_value(&kdf).unwrap()).unwrap();
        let recovery_kdf_bytes =
            canonical_json_bytes(&serde_json::to_value(&recovery_kdf).unwrap()).unwrap();
        assert_eq!(
            std::str::from_utf8(&kdf_bytes).unwrap(),
            r#"{"algorithm":"argon2id","memory_kib":65536,"output_len":32,"parallelism":1,"salt":"AAECAwQFBgcICQoLDA0ODw==","time_cost":2,"version":1}"#
        );
        assert_eq!(
            std::str::from_utf8(&recovery_kdf_bytes).unwrap(),
            r#"{"algorithm":"argon2id","memory_kib":19456,"output_len":32,"parallelism":1,"salt":"EBESExQVFhcYGRobHB0eHw==","time_cost":2,"version":1}"#
        );
        let digest = digest_account_secrets_blob(
            &kdf_bytes,
            &recovery_kdf_bytes,
            b"account-key-wrap",
            b"account-kem-private-wrap",
            b"account-signing-private-wrap",
            b"recovery-key-wrap",
        );
        assert_eq!(
            hex::encode(digest),
            "fae568042e67d25db5c6e921d4c1e12eb3245287c9e5d0de68ff08d04fba4b05"
        );
    }

    #[test]
    fn canonical_json_bytes_sorts_object_keys_recursively() {
        let a: Value =
            serde_json::from_str(r#"{"z":1,"a":{"y":true,"b":[{"d":4,"c":3}]}}"#).unwrap();
        let b: Value =
            serde_json::from_str(r#"{"a":{"b":[{"c":3,"d":4}],"y":true},"z":1}"#).unwrap();
        let bytes = canonical_json_bytes(&a).unwrap();
        assert_eq!(bytes, canonical_json_bytes(&b).unwrap());
        assert_eq!(bytes, br#"{"a":{"b":[{"c":3,"d":4}],"y":true},"z":1}"#);
    }

    #[test]
    fn canonical_json_bytes_pins_scalar_forms() {
        let value: Value = serde_json::from_str(r#"{"z":null,"n":1,"s":"line\nbreak"}"#).unwrap();
        let bytes = canonical_json_bytes(&value).unwrap();
        assert_eq!(bytes, br#"{"n":1,"s":"line\nbreak","z":null}"#);
    }

    #[test]
    fn canonical_json_bytes_rejects_float_numbers() {
        let value: Value = serde_json::from_str(r#"{"memory_kib":65536.0}"#).unwrap();
        let err = canonical_json_bytes(&value).unwrap_err();
        assert!(matches!(
            err,
            crate::error::CryptoError::Canonicalization(_)
        ));
    }

    #[test]
    fn canonical_wire_shape() {
        let user = Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap();
        let proof = AccountSecretsUpdateProof {
            user_id: user,
            issued_at: Timestamp::UNIX_EPOCH,
            blob_digest: [0xABu8; 32],
        };
        let bytes = canonical(&proof);
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"seren-secrets-account-secrets-update\n");
        expected.extend_from_slice(b"user_id=11111111-2222-3333-4444-555555555555\n");
        expected.extend_from_slice(b"issued_at=1970-01-01T00:00:00Z\n");
        expected.extend_from_slice(b"blob_digest=");
        expected.extend_from_slice(&[0xABu8; 32]);
        expected.push(b'\n');
        assert_eq!(bytes, expected);
    }
}

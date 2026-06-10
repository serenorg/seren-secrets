//! Membership-grant signing.
//!
//! A vault membership grant binds (vault, grantee identity, access level,
//! wrapped vault key) under the granter's identity signing key. The signature
//! makes the grant tuple attributable and tamper-evident instead of relying on
//! an unauthenticated key wrap alone.
//!
//! The byte layout and access-level bytes are frozen protocol commitments
//! shared with the seren-passwords service, which verifies them
//! independently; changing either requires a coordinated protocol bump.

use crate::error::CryptoResult;
use crate::keys::{IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::signing;

/// Domain-separation prefix for membership-grant signatures.
pub const MEMBERSHIP_GRANT_DOMAIN: &[u8] = b"seren-secrets/membership-grant";

/// Access-level bytes are fixed protocol data: a grant signed for one level
/// must not verify for another.
pub const ACCESS_LEVEL_READ: u8 = 1;
pub const ACCESS_LEVEL_WRITE: u8 = 2;
pub const ACCESS_LEVEL_ADMIN: u8 = 3;

/// Map the canonical snake_case access-level string to its protocol byte.
pub fn access_level_byte(access_level: &str) -> Option<u8> {
    match access_level {
        "read" => Some(ACCESS_LEVEL_READ),
        "write" => Some(ACCESS_LEVEL_WRITE),
        "admin" => Some(ACCESS_LEVEL_ADMIN),
        _ => None,
    }
}

/// Canonical signed bytes for a membership grant:
///
///   "seren-secrets/membership-grant" || vault_uuid_bytes(16)
///     || identity_uuid_bytes(16) || access_level_byte(1)
///     || wrapped_vault_key_bytes(var)
///
/// Every field is fixed-width except the trailing wrapped key, so the
/// encoding is unambiguous without length prefixes.
pub fn membership_grant_signing_bytes(
    vault_id: &[u8; 16],
    identity_id: &[u8; 16],
    access_level: u8,
    wrapped_vault_key: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(MEMBERSHIP_GRANT_DOMAIN.len() + 16 + 16 + 1 + wrapped_vault_key.len());
    out.extend_from_slice(MEMBERSHIP_GRANT_DOMAIN);
    out.extend_from_slice(vault_id);
    out.extend_from_slice(identity_id);
    out.push(access_level);
    out.extend_from_slice(wrapped_vault_key);
    out
}

/// Sign a membership grant with the granter's identity signing key.
/// Returns the wire-enveloped Ed25519 signature.
pub fn sign_membership_grant(
    granter: &IdentitySigningPrivateKey,
    vault_id: &[u8; 16],
    identity_id: &[u8; 16],
    access_level: u8,
    wrapped_vault_key: &[u8],
) -> Vec<u8> {
    let payload =
        membership_grant_signing_bytes(vault_id, identity_id, access_level, wrapped_vault_key);
    signing::sign(granter, &payload)
}

/// Verify a membership-grant signature against the granter's identity
/// signing public key.
pub fn verify_membership_grant(
    granter: &IdentitySigningPublicKey,
    vault_id: &[u8; 16],
    identity_id: &[u8; 16],
    access_level: u8,
    wrapped_vault_key: &[u8],
    signature: &[u8],
) -> CryptoResult<()> {
    let payload =
        membership_grant_signing_bytes(vault_id, identity_id, access_level, wrapped_vault_key);
    signing::verify(granter, &payload, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;
    use crate::keys::{
        IdentitySigningKeypair, IdentitySigningPrivateKey, IdentitySigningPublicKey,
    };

    #[test]
    fn signing_bytes_layout_is_pinned() {
        // Frozen protocol commitment: the seren-passwords service rebuilds
        // these bytes independently, and the wasm bindings expose the same
        // layout. Any change here is a breaking protocol bump.
        let signed = membership_grant_signing_bytes(&[1; 16], &[2; 16], 3, &[4, 5]);
        assert!(signed.starts_with(b"seren-secrets/membership-grant"));
        assert_eq!(
            &signed[b"seren-secrets/membership-grant".len()..],
            &[
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 3, 4, 5,
            ]
        );
    }

    #[test]
    fn access_level_bytes_are_pinned() {
        assert_eq!(access_level_byte("read"), Some(ACCESS_LEVEL_READ));
        assert_eq!(access_level_byte("write"), Some(ACCESS_LEVEL_WRITE));
        assert_eq!(access_level_byte("admin"), Some(ACCESS_LEVEL_ADMIN));
        assert_eq!(access_level_byte("Read"), None);
        assert_eq!(access_level_byte(""), None);
        assert_eq!(
            (ACCESS_LEVEL_READ, ACCESS_LEVEL_WRITE, ACCESS_LEVEL_ADMIN),
            (1, 2, 3)
        );
    }

    #[test]
    fn sign_verify_round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let vault = [7u8; 16];
        let grantee = [8u8; 16];
        let wrapped = vec![9u8; 80];
        let sig = sign_membership_grant(&kp.private, &vault, &grantee, ACCESS_LEVEL_READ, &wrapped);
        verify_membership_grant(
            &kp.public,
            &vault,
            &grantee,
            ACCESS_LEVEL_READ,
            &wrapped,
            &sig,
        )
        .unwrap();
    }

    #[test]
    fn known_answer_vector_is_pinned() {
        let private = IdentitySigningPrivateKey::from_bytes([0x42; 32]);
        let signing = ed25519_dalek::SigningKey::from_bytes(private.as_bytes());
        let public = IdentitySigningPublicKey::from_bytes(signing.verifying_key().to_bytes());
        let vault = [0x11; 16];
        let grantee = [0x22; 16];
        let wrapped = [0x33; 32];
        let signed = membership_grant_signing_bytes(&vault, &grantee, ACCESS_LEVEL_WRITE, &wrapped);
        let signature =
            sign_membership_grant(&private, &vault, &grantee, ACCESS_LEVEL_WRITE, &wrapped);

        assert_eq!(
            hex::encode(&signed),
            "736572656e2d736563726574732f6d656d626572736869702d6772616e741111111111111111111111111111111122222222222222222222222222222222023333333333333333333333333333333333333333333333333333333333333333",
        );
        assert_eq!(
            hex::encode(&signature),
            "0104e887d29544fae690c8c7a847f983791346db87d5c3f2329107b8ebc3af65819c6f7e93d27704e237b90c0dc0ea387f4f6e3d1b5a57c7dc1675bb5d197537ef08",
        );
        verify_membership_grant(
            &public,
            &vault,
            &grantee,
            ACCESS_LEVEL_WRITE,
            &wrapped,
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn tampered_fields_fail_verification() {
        let kp = IdentitySigningKeypair::generate();
        let vault = [7u8; 16];
        let grantee = [8u8; 16];
        let wrapped = vec![9u8; 80];
        let sig = sign_membership_grant(&kp.private, &vault, &grantee, ACCESS_LEVEL_READ, &wrapped);

        // Access-level escalation must not verify.
        let err = verify_membership_grant(
            &kp.public,
            &vault,
            &grantee,
            ACCESS_LEVEL_ADMIN,
            &wrapped,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));

        // A swapped grantee must not verify.
        let err = verify_membership_grant(
            &kp.public,
            &vault,
            &[1; 16],
            ACCESS_LEVEL_READ,
            &wrapped,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));

        // A substituted wrapped key must not verify.
        let err = verify_membership_grant(
            &kp.public,
            &vault,
            &grantee,
            ACCESS_LEVEL_READ,
            &[0u8; 80],
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));

        // A different signer must not verify.
        let other = IdentitySigningKeypair::generate();
        let err = verify_membership_grant(
            &other.public,
            &vault,
            &grantee,
            ACCESS_LEVEL_READ,
            &wrapped,
            &sig,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }
}

//! Signed `POST /resolve` request canonical form.
//!
//! The upstream secrets service requires every resolve call to carry an Ed25519 signature
//! by the caller's identity signing key over the request canonical bytes. The
//! server verifies the signature before handing back any wrapped material and
//! binds the signature to the caller and timestamp so a captured signature
//! cannot be replayed against a different agent identity or after a short
//! window. The audit row records that the call happened but does not store
//! the signature itself.

use jiff::Timestamp;
use uuid::Uuid;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::signing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRequest {
    /// `seren-secrets://<vault>/<item>/<field>` reference.
    pub uri: String,
    /// Caller identity at the time of the call. Bound into the signature so
    /// a captured signature cannot be replayed under a different identity.
    pub caller_identity_id: Uuid,
    /// RFC3339 timestamp; the server rejects requests outside a small window.
    pub issued_at: Timestamp,
    /// Single-use nonce consumed by the service after signature verification.
    pub nonce: Uuid,
}

/// Hand-rolled ASCII canonical form. Avoids the open question of serde_json
/// field-order stability.
///
/// `\n` separates fields, so the `uri` value must not embed `\n` or `\r`;
/// otherwise distinct logical requests could share the same canonical bytes
/// and a single signature could authorize multiple resolves.
fn canonical(req: &ResolveRequest) -> CryptoResult<Vec<u8>> {
    if req.uri.contains('\n') || req.uri.contains('\r') {
        return Err(CryptoError::MalformedWire(
            "resolve uri must not contain CR or LF",
        ));
    }
    let ts = req.issued_at.to_string();
    Ok(format!(
        "seren-secrets-resolve\nuri={}\ncaller_identity_id={}\nissued_at={}\nnonce={}\n",
        req.uri, req.caller_identity_id, ts, req.nonce
    )
    .into_bytes())
}

/// Build the caller's Ed25519 signature over the canonical resolve request.
///
/// Replay defense is server-side: enforce a tight `issued_at` window and
/// consume each canonical request at most once.
pub fn build_resolve_signature(
    private: &IdentitySigningPrivateKey,
    request: &ResolveRequest,
) -> CryptoResult<Vec<u8>> {
    Ok(signing::sign(private, &canonical(request)?))
}

pub fn verify_resolve_signature(
    public: &IdentitySigningPublicKey,
    request: &ResolveRequest,
    signature: &[u8],
) -> CryptoResult<()> {
    signing::verify(public, &canonical(request)?, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentitySigningKeypair;
    use jiff::SignedDuration;

    fn sample(uri: &str, caller: Uuid) -> ResolveRequest {
        ResolveRequest {
            uri: uri.to_string(),
            caller_identity_id: caller,
            issued_at: Timestamp::from_second(1_700_000_000).unwrap(),
            nonce: Uuid::from_u128(4),
        }
    }

    #[test]
    fn round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let req = sample(
            "seren-secrets://11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/password",
            Uuid::new_v4(),
        );
        let sig = build_resolve_signature(&kp.private, &req).unwrap();
        verify_resolve_signature(&kp.public, &req, &sig).unwrap();
    }

    #[test]
    fn wrong_signer_fails() {
        let kp1 = IdentitySigningKeypair::generate();
        let kp2 = IdentitySigningKeypair::generate();
        let req = sample("seren-secrets://a/b/c", Uuid::new_v4());
        let sig = build_resolve_signature(&kp1.private, &req).unwrap();
        let err = verify_resolve_signature(&kp2.public, &req, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_uri_fails() {
        let kp = IdentitySigningKeypair::generate();
        let caller = Uuid::new_v4();
        let req = sample("seren-secrets://a/b/c", caller);
        let sig = build_resolve_signature(&kp.private, &req).unwrap();
        let mut tampered = req.clone();
        tampered.uri = "seren-secrets://x/y/z".into();
        let err = verify_resolve_signature(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_caller_fails() {
        let kp = IdentitySigningKeypair::generate();
        let req = sample("seren-secrets://a/b/c", Uuid::new_v4());
        let sig = build_resolve_signature(&kp.private, &req).unwrap();
        let mut tampered = req.clone();
        tampered.caller_identity_id = Uuid::new_v4();
        let err = verify_resolve_signature(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_timestamp_fails() {
        let kp = IdentitySigningKeypair::generate();
        let req = sample("seren-secrets://a/b/c", Uuid::new_v4());
        let sig = build_resolve_signature(&kp.private, &req).unwrap();
        let mut tampered = req.clone();
        tampered.issued_at = tampered
            .issued_at
            .checked_add(SignedDuration::from_secs(1))
            .unwrap();
        let err = verify_resolve_signature(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    #[test]
    fn tampered_nonce_fails() {
        let kp = IdentitySigningKeypair::generate();
        let req = sample("seren-secrets://a/b/c", Uuid::new_v4());
        let sig = build_resolve_signature(&kp.private, &req).unwrap();
        let mut tampered = req.clone();
        tampered.nonce = Uuid::new_v4();
        let err = verify_resolve_signature(&kp.public, &tampered, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }

    /// Pin the exact canonical wire shape that the service and clients sign
    /// over. Changing this is a wire-protocol break.
    #[test]
    fn canonical_wire_shape() {
        let caller = Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap();
        let req = ResolveRequest {
            uri: "seren-secrets://aaaa/bbbb/password".to_string(),
            caller_identity_id: caller,
            issued_at: Timestamp::UNIX_EPOCH,
            nonce: Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
        };
        let bytes = canonical(&req).unwrap();
        let expected = concat!(
            "seren-secrets-resolve\n",
            "uri=seren-secrets://aaaa/bbbb/password\n",
            "caller_identity_id=33333333-3333-3333-3333-333333333333\n",
            "issued_at=1970-01-01T00:00:00Z\n",
            "nonce=44444444-4444-4444-8444-444444444444\n",
        );
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), expected,);
    }

    /// A `uri` containing `\n` would let a single signature authorize two
    /// distinct logical requests because the canonical bytes would collide
    /// with a different (uri, caller, issued_at) triple.
    #[test]
    fn rejects_uri_with_newline() {
        let kp = IdentitySigningKeypair::generate();
        let req = ResolveRequest {
            uri: "seren-secrets://a/b/c\ncaller_identity_id=evil".to_string(),
            caller_identity_id: Uuid::new_v4(),
            issued_at: Timestamp::UNIX_EPOCH,
            nonce: Uuid::new_v4(),
        };
        let err = build_resolve_signature(&kp.private, &req).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::MalformedWire(_)));
        let err = verify_resolve_signature(&kp.public, &req, &[0u8; 64]).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::MalformedWire(_)));
    }

    #[test]
    fn rejects_uri_with_carriage_return() {
        let kp = IdentitySigningKeypair::generate();
        let req = ResolveRequest {
            uri: "seren-secrets://a/b/c\rinjected".to_string(),
            caller_identity_id: Uuid::new_v4(),
            issued_at: Timestamp::UNIX_EPOCH,
            nonce: Uuid::new_v4(),
        };
        let err = build_resolve_signature(&kp.private, &req).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::MalformedWire(_)));
    }
}

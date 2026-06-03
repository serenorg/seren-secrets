//! Signed approval requests for policy-gated secret access.
//!
//! Only the agent `ApprovalRequest` is signed today:
//! 1. The agent builds and signs an `ApprovalRequest`.
//! 2. The approver validates the request and grants access out of band.
//! 3. The requester retries after the approval is active.
//!
//! Grant binding is server-enforced until the wire protocol adds a signed
//! `ApprovalGrant`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CryptoResult;
use crate::keys::{IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::signing;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalTarget {
    Vault { vault_id: Uuid },
    Item { vault_id: Uuid, item_id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: Uuid,
    pub requesting_identity_id: Uuid,
    pub target: ApprovalTarget,
    /// Seconds the agent is willing to wait for approval.
    pub timeout_seconds: u32,
}

/// Canonical bytes for signing. This is a hand-rolled ASCII format so
/// signatures do not depend on serde_json object field ordering.
fn canonical_request(request: &ApprovalRequest) -> Vec<u8> {
    let (target_kind, vault_id, item_id) = match request.target {
        ApprovalTarget::Vault { vault_id } => ("vault", vault_id, None),
        ApprovalTarget::Item { vault_id, item_id } => ("item", vault_id, Some(item_id)),
    };
    let item = item_id.map(|id| id.to_string()).unwrap_or_default();
    format!(
        "approval-request\nrequest_id={}\nrequesting_identity_id={}\ntarget_kind={}\nvault_id={}\nitem_id={}\ntimeout_seconds={}\n",
        request.request_id,
        request.requesting_identity_id,
        target_kind,
        vault_id,
        item,
        request.timeout_seconds
    )
    .into_bytes()
}

pub fn build_approval_request(
    private: &IdentitySigningPrivateKey,
    request: &ApprovalRequest,
) -> Vec<u8> {
    signing::sign(private, &canonical_request(request))
}

pub fn verify_approval_request(
    public: &IdentitySigningPublicKey,
    request: &ApprovalRequest,
    signature: &[u8],
) -> CryptoResult<()> {
    signing::verify(public, &canonical_request(request), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentitySigningKeypair;

    #[test]
    fn round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let req = ApprovalRequest {
            request_id: Uuid::new_v4(),
            requesting_identity_id: Uuid::new_v4(),
            target: ApprovalTarget::Vault {
                vault_id: Uuid::new_v4(),
            },
            timeout_seconds: 60,
        };
        let sig = build_approval_request(&kp.private, &req);
        verify_approval_request(&kp.public, &req, &sig).unwrap();
    }

    #[test]
    fn tampered_request_fails() {
        let kp = IdentitySigningKeypair::generate();
        let mut req = ApprovalRequest {
            request_id: Uuid::new_v4(),
            requesting_identity_id: Uuid::new_v4(),
            target: ApprovalTarget::Vault {
                vault_id: Uuid::new_v4(),
            },
            timeout_seconds: 60,
        };
        let sig = build_approval_request(&kp.private, &req);
        req.timeout_seconds = 120;
        let err = verify_approval_request(&kp.public, &req, &sig).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::InvalidSignature));
    }
}

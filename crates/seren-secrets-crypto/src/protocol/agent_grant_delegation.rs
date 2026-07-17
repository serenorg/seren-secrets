//! Canonical user-signed delegation for hosted agent secret resolution.

use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{IdentityKemPublicKey, IdentitySigningPrivateKey};
use crate::signing;

const DOMAIN: &[u8] = b"seren-secrets-gateway/agent-grant-delegation";
const DEFAULT_STRING_MAX: usize = 4096;
const DEFAULT_BYTES_MAX: usize = 1024 * 1024;
const ITEM_KEY_WRAP_MAX: usize = 4096;
const SIGNER_KEY_ID_MAX: usize = 128;
const LIST_MAX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrantDelegationScope {
    pub user_id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub agent_identity_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrantDelegationEntry {
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub field: String,
    pub item_key_wrap: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrantDelegation {
    pub scope: AgentGrantDelegationScope,
    pub agent_kem_public_key: IdentityKemPublicKey,
    pub delegation_id: Uuid,
    pub delegate_signer_key_id: String,
    pub entries: Vec<AgentGrantDelegationEntry>,
    pub not_before: i64,
    pub expires_at: i64,
    pub max_grant_ttl_seconds: u64,
    pub delegation_epoch: u64,
}

/// Encode and sign the delegation using the frozen Secrets Gateway wire format.
pub fn sign_agent_grant_delegation(
    signing_private_key: &IdentitySigningPrivateKey,
    delegation: &AgentGrantDelegation,
) -> CryptoResult<Vec<u8>> {
    if delegation.not_before < 0
        || delegation.expires_at < 0
        || delegation.expires_at <= delegation.not_before
    {
        return Err(CryptoError::Canonicalization(
            "invalid delegation time window",
        ));
    }
    if delegation.max_grant_ttl_seconds == 0 {
        return Err(CryptoError::Canonicalization(
            "max grant ttl must be greater than zero",
        ));
    }
    if delegation.entries.is_empty() {
        return Err(CryptoError::Canonicalization(
            "delegation entries must not be empty",
        ));
    }
    if delegation.entries.len() > LIST_MAX {
        return Err(CryptoError::Canonicalization(
            "delegation entries exceed max length",
        ));
    }

    let mut entries = delegation.entries.clone();
    entries.sort_by(|left, right| {
        (left.vault_id, left.item_id, left.field.as_bytes()).cmp(&(
            right.vault_id,
            right.item_id,
            right.field.as_bytes(),
        ))
    });
    for entry in &entries {
        validate_entry(entry)?;
    }
    for pair in entries.windows(2) {
        if pair[0].vault_id == pair[1].vault_id
            && pair[0].item_id == pair[1].item_id
            && pair[0].field == pair[1].field
        {
            return Err(CryptoError::Canonicalization(
                "delegation entries must be unique",
            ));
        }
    }

    let mut body = SceWriter::new();
    body.raw(delegation.scope.user_id.as_bytes());
    body.raw(delegation.scope.organization_id.as_bytes());
    match delegation.scope.workspace_id {
        Some(workspace_id) => {
            body.u8(1);
            body.raw(workspace_id.as_bytes());
        }
        None => body.u8(0),
    }
    body.raw(delegation.scope.agent_identity_id.as_bytes());
    body.raw(delegation.agent_kem_public_key.as_bytes());
    body.raw(delegation.delegation_id.as_bytes());
    body.bytes_with_max(
        delegation.delegate_signer_key_id.as_bytes(),
        SIGNER_KEY_ID_MAX,
    )?;
    body.list_len(entries.len())?;
    for entry in &entries {
        body.raw(entry.vault_id.as_bytes());
        body.raw(entry.item_id.as_bytes());
        body.string(&entry.field)?;
        body.bytes_with_max(&entry.item_key_wrap, ITEM_KEY_WRAP_MAX)?;
        body.list_len(0)?;
    }
    body.i64(delegation.not_before);
    body.i64(delegation.expires_at);
    body.u64(delegation.max_grant_ttl_seconds);
    body.u64(delegation.delegation_epoch);

    let mut canonical = body.finish();
    let mut signing_input = SceWriter::new();
    signing_input.bytes(DOMAIN)?;
    signing_input.raw(&canonical);
    let signature = signing::sign(signing_private_key, &signing_input.finish());
    let mut signature_wire = SceWriter::new();
    signature_wire.bytes(&signature)?;
    canonical.extend_from_slice(&signature_wire.finish());
    Ok(canonical)
}

fn validate_entry(entry: &AgentGrantDelegationEntry) -> CryptoResult<()> {
    if entry.field.is_empty()
        || entry.field.contains('/')
        || entry.field.contains('?')
        || entry.field.contains('#')
        || entry.field.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        return Err(CryptoError::Canonicalization(
            "invalid delegation entry field",
        ));
    }
    if entry.item_key_wrap.is_empty() {
        return Err(CryptoError::Canonicalization(
            "item key wrap must not be empty",
        ));
    }
    Ok(())
}

struct SceWriter {
    out: Vec<u8>,
}

impl SceWriter {
    fn new() -> Self {
        Self { out: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }

    fn raw(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn list_len(&mut self, value: usize) -> CryptoResult<()> {
        if value > LIST_MAX {
            return Err(CryptoError::Canonicalization("list length exceeds max"));
        }
        self.u32(value as u32);
        Ok(())
    }

    fn string(&mut self, value: &str) -> CryptoResult<()> {
        if value.nfc().ne(value.chars()) {
            return Err(CryptoError::Canonicalization(
                "string must be NFC-normalized",
            ));
        }
        self.bytes_with_max(value.as_bytes(), DEFAULT_STRING_MAX)
    }

    fn bytes(&mut self, value: &[u8]) -> CryptoResult<()> {
        self.bytes_with_max(value, DEFAULT_BYTES_MAX)
    }

    fn bytes_with_max(&mut self, value: &[u8], max: usize) -> CryptoResult<()> {
        if value.len() > max {
            return Err(CryptoError::Canonicalization("bytes exceed max length"));
        }
        let len = u32::try_from(value.len())
            .map_err(|_| CryptoError::Canonicalization("bytes exceed wire length"))?;
        self.u32(len);
        self.raw(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{IdentityKemKeypair, IdentitySigningKeypair};

    fn delegation() -> (IdentitySigningKeypair, AgentGrantDelegation) {
        let signing = IdentitySigningKeypair::from_private(
            crate::keys::IdentitySigningPrivateKey::from_bytes([7; 32]),
        );
        let kem = IdentityKemKeypair::from_private(crate::keys::IdentityKemPrivateKey::from_bytes(
            [9; 32],
        ));
        (
            signing,
            AgentGrantDelegation {
                scope: AgentGrantDelegationScope {
                    user_id: Uuid::from_u128(1),
                    organization_id: Uuid::from_u128(2),
                    workspace_id: None,
                    agent_identity_id: Uuid::from_u128(3),
                },
                agent_kem_public_key: kem.public,
                delegation_id: Uuid::from_u128(4),
                delegate_signer_key_id: "grant-delegate".to_string(),
                entries: vec![AgentGrantDelegationEntry {
                    vault_id: Uuid::from_u128(5),
                    item_id: Uuid::from_u128(6),
                    field: "token".to_string(),
                    item_key_wrap: vec![1, 2, 3],
                }],
                not_before: 100,
                expires_at: 200,
                max_grant_ttl_seconds: 60,
                delegation_epoch: 1,
            },
        )
    }

    #[test]
    fn signing_is_deterministic_and_rejects_duplicate_entries() {
        let (signing, mut delegation) = delegation();
        let first = sign_agent_grant_delegation(&signing.private, &delegation).unwrap();
        let second = sign_agent_grant_delegation(&signing.private, &delegation).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            hex::encode(&first),
            "0000000000000000000000000000000100000000000000000000000000000002000000000000000000000000000000000357db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d421000000000000000000000000000000040000000e6772616e742d64656c656761746500000001000000000000000000000000000000050000000000000000000000000000000600000005746f6b656e0000000301020300000000000000000000006400000000000000c8000000000000003c0000000000000001000000420104e540010ffaaa78508a815994d002339d33980dda8b7dcd9c066fe4336cceced0e0fc84e8e0dd6b9dc08df21e1d308839f5cfbee46e35e8acdfa93a3fd3ab0306"
        );

        delegation.entries.push(delegation.entries[0].clone());
        assert!(sign_agent_grant_delegation(&signing.private, &delegation).is_err());
    }
}

//! Browser-only proposals and their opaque Core commitment. Never persist the
//! proposal in the Passwords service: it contains customer vault metadata.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use super::{
    AgentDelegationAccessLevel, MAX_PROVISIONED_VAULTS, VaultProvisioningBinding,
    canonical_json_bytes,
};
use crate::error::{CryptoError, CryptoResult};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedProvisioningVault {
    pub key: String,
    pub name: String,
    pub description: String,
    pub access_level: AgentDelegationAccessLevel,
    pub source: ProvisioningVaultSource,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ProvisioningVaultSource {
    #[serde(rename = "1password")]
    OnePassword {
        vault_id: String,
        account_id: String,
    },
}

/// Hash the validated list with the shared recursive JSON canonicalizer. Object
/// keys are sorted; list order is preserved. Core and WASM use these exact bytes.
pub fn vault_provisioning_binding(
    requested: &[RequestedProvisioningVault],
) -> CryptoResult<VaultProvisioningBinding> {
    let invalid = || CryptoError::Canonicalization("invalid vault provisioning proposal");
    if requested.is_empty() || requested.len() > MAX_PROVISIONED_VAULTS {
        return Err(invalid());
    }
    let mut keys = BTreeSet::new();
    for vault in requested {
        let ProvisioningVaultSource::OnePassword {
            account_id,
            vault_id,
        } = &vault.source;
        let source_id = |s: &str| {
            !s.is_empty()
                && s.len() <= 256
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        if vault.key.trim().is_empty()
            || vault.key.len() > 4096
            || !keys.insert(vault.key.clone())
            || vault.name.trim().is_empty()
            || vault.name.chars().count() > 120
            || vault.description.len() > 4096
            || vault.access_level != AgentDelegationAccessLevel::Write
            || !source_id(account_id)
            || !source_id(vault_id)
        {
            return Err(invalid());
        }
    }
    let value = serde_json::to_value(requested).map_err(|_| invalid())?;
    let canonical = canonical_json_bytes(&value)?;
    let binding = VaultProvisioningBinding {
        keys: keys.into_iter().collect(),
        vault_count: requested.len() as u16,
        payload_digest: Sha256::digest(canonical)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    };
    binding.validate()?;
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROPOSAL: &str = r#"[{"key":"opaque","name":"Fixture vault","description":"Fixture description","access_level":"write","source":{"kind":"1password","vault_id":"fixture-vault","account_id":"fixture-account"}}]"#;
    #[test]
    fn proposal_commitment_covers_customer_metadata_and_rejects_invalid_scope() {
        let requested: Vec<RequestedProvisioningVault> = serde_json::from_str(PROPOSAL).unwrap();
        let bound = vault_provisioning_binding(&requested).unwrap();
        assert_eq!(bound.keys, vec!["opaque"]);
        let mut changed = requested.clone();
        changed[0].name.push('!');
        assert_ne!(bound, vault_provisioning_binding(&changed).unwrap());
        changed[0].access_level = AgentDelegationAccessLevel::Read;
        assert!(vault_provisioning_binding(&changed).is_err());
        assert!(vault_provisioning_binding(&[requested[0].clone(), requested[0].clone()]).is_err());
        changed[0] = requested[0].clone();
        changed[0].name = "x".repeat(121);
        assert!(vault_provisioning_binding(&changed).is_err());
        assert!(vault_provisioning_binding(&[]).is_err());
        assert!(
            serde_json::from_str::<Vec<RequestedProvisioningVault>>(
                &PROPOSAL.replace("1password", "unknown")
            )
            .is_err()
        );
        let reordered =
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(PROPOSAL).unwrap())
                .unwrap();
        assert_eq!(
            bound,
            vault_provisioning_binding(
                &serde_json::from_str::<Vec<RequestedProvisioningVault>>(&reordered).unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            bound.payload_digest,
            Sha256::digest(canonical_json_bytes(&serde_json::from_str(PROPOSAL).unwrap()).unwrap())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
    }
}

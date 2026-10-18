//! Canonical contribution payloads for multi-principal agent delegation.
//!
//! The browser constructs these bytes from the participant context and the user's
//! selected mappings before it asks the identity key to sign. The Passwords
//! service uses the same builder when it verifies the contribution. Keeping
//! this builder in the shared crypto crate prevents a browser client from
//! treating server-chosen signing bytes as authoritative.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

use crate::error::{CryptoError, CryptoResult};
use crate::keys::IdentitySigningPrivateKey;
use crate::signing;

pub const AGENT_DELEGATION_CONTRIBUTION_DOMAIN: &str =
    "seren-secrets/agent-delegation-policy-contribution";

const MAX_MAPPINGS: usize = 1024;
const MAX_VAULT_GRANTS: usize = 1024;
const MAX_OPAQUE_WRAP_BYTES: usize = 4096;
const MAX_SIGNATURE_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_PROVISIONED_VAULTS: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDelegationDecision {
    Approve,
    Decline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDelegationScopeKind {
    SecretFields,
    VaultAccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDelegationTargetKind {
    Existing,
    Bootstrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDelegationAccessLevel {
    Read,
    Write,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDelegationFieldMapping {
    pub environment_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_group: Option<String>,
    pub vault_id: Uuid,
    pub item_id: Uuid,
    pub field: String,
    #[serde(with = "base64_bytes")]
    pub item_key_wrap: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDelegationVaultGrant {
    pub vault_id: Uuid,
    pub access_level: AgentDelegationAccessLevel,
    #[serde(with = "base64_bytes")]
    pub wrapped_vault_key: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub granted_signature: Vec<u8>,
}

/// Opaque commitment to the owner's browser-only vault proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultProvisioningBinding {
    pub keys: Vec<String>,
    pub vault_count: u16,
    pub payload_digest: String,
}

impl VaultProvisioningBinding {
    pub fn validate(&self) -> CryptoResult<()> {
        if self.keys.is_empty()
            || self.keys.len() > MAX_PROVISIONED_VAULTS
            || self.keys.len() != usize::from(self.vault_count)
            || self
                .keys
                .iter()
                .any(|key| key.trim().is_empty() || key.len() > MAX_TEXT_BYTES)
            || self.keys.iter().collect::<BTreeSet<_>>().len() != self.keys.len()
            || self.payload_digest.len() != 64
            || !self
                .payload_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CryptoError::Canonicalization(
                "invalid vault provisioning binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultProvisioningGrantLifetime {
    UntilRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedVault {
    pub key: String,
    pub vault_id: Uuid,
    pub adopted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDelegationVaultProvisioning {
    pub binding: VaultProvisioningBinding,
    pub grant_lifetime: VaultProvisioningGrantLifetime,
    pub provisioned_vaults: Vec<ProvisionedVault>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDelegationContribution {
    pub request_id: Uuid,
    pub result_id: Uuid,
    pub destination_organization_id: Uuid,
    pub scope_kind: AgentDelegationScopeKind,
    pub deployment_id: Option<Uuid>,
    pub deployment_revision_id: Option<Uuid>,
    pub agent_identity_id: Uuid,
    pub agent_target_kind: AgentDelegationTargetKind,
    #[serde(with = "base64_bytes")]
    pub agent_kem_fingerprint: Vec<u8>,
    #[serde(with = "base64_bytes")]
    pub agent_signing_fingerprint: Vec<u8>,
    pub allowed_access_levels: Vec<AgentDelegationAccessLevel>,
    pub request_nonce: String,
    pub expires_at_unix_seconds: i64,
    pub participant_id: Uuid,
    pub role: String,
    pub stage: u16,
    pub actor_organization_id: Uuid,
    pub actor_user_id: Uuid,
    pub actor_identity_id: Uuid,
    pub contribution_id: Uuid,
    pub decision: AgentDelegationDecision,
    #[serde(default)]
    pub mappings: Vec<AgentDelegationFieldMapping>,
    #[serde(default)]
    pub vault_grants: Vec<AgentDelegationVaultGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_provisioning: Option<AgentDelegationVaultProvisioning>,
}

#[derive(Serialize)]
struct CanonicalContribution<'a> {
    domain: &'static str,
    request_id: Uuid,
    result_id: Uuid,
    destination_organization_id: Uuid,
    scope_kind: AgentDelegationScopeKind,
    deployment_id: Option<Uuid>,
    deployment_revision_id: Option<Uuid>,
    agent_identity_id: Uuid,
    agent_target_kind: AgentDelegationTargetKind,
    agent_kem_fingerprint_b64: String,
    agent_signing_fingerprint_b64: String,
    allowed_access_levels: &'a [AgentDelegationAccessLevel],
    request_nonce: &'a str,
    expires_at_unix_seconds: i64,
    participant_id: Uuid,
    role: &'a str,
    stage: u16,
    actor_organization_id: Uuid,
    actor_user_id: Uuid,
    actor_identity_id: Uuid,
    contribution_id: Uuid,
    decision: AgentDelegationDecision,
    mappings: &'a [AgentDelegationFieldMapping],
    vault_grants: &'a [AgentDelegationVaultGrant],
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_provisioning: Option<&'a AgentDelegationVaultProvisioning>,
}

/// Build the exact JSON bytes an agent delegation participant signs.
///
/// Mapping and vault-grant order are canonicalized here so callers cannot
/// accidentally sign a semantically identical contribution in a wire order
/// the Passwords verifier will normalize differently.
pub fn agent_delegation_contribution_payload(
    mut contribution: AgentDelegationContribution,
) -> CryptoResult<Vec<u8>> {
    validate_contribution(&contribution)?;
    contribution.mappings.sort_by(|left, right| {
        (
            &left.environment_name,
            &left.field_group,
            left.vault_id,
            left.item_id,
            &left.field,
        )
            .cmp(&(
                &right.environment_name,
                &right.field_group,
                right.vault_id,
                right.item_id,
                &right.field,
            ))
    });
    contribution
        .vault_grants
        .sort_unstable_by_key(|grant| (grant.vault_id, grant.access_level));
    contribution.allowed_access_levels.sort_unstable();
    if let Some(provisioning) = &mut contribution.vault_provisioning {
        provisioning.binding.keys.sort_unstable();
        provisioning
            .provisioned_vaults
            .sort_unstable_by(|a, b| a.key.cmp(&b.key));
    }

    if contribution
        .allowed_access_levels
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(CryptoError::Canonicalization(
            "duplicate delegation access level",
        ));
    }

    if contribution
        .mappings
        .windows(2)
        .any(|pair| pair[0].environment_name == pair[1].environment_name)
    {
        return Err(CryptoError::Canonicalization(
            "duplicate delegation environment mapping",
        ));
    }
    if contribution
        .vault_grants
        .windows(2)
        .any(|pair| pair[0].vault_id == pair[1].vault_id)
    {
        return Err(CryptoError::Canonicalization(
            "duplicate delegation vault grant",
        ));
    }

    serde_json::to_vec(&CanonicalContribution {
        domain: AGENT_DELEGATION_CONTRIBUTION_DOMAIN,
        request_id: contribution.request_id,
        result_id: contribution.result_id,
        destination_organization_id: contribution.destination_organization_id,
        scope_kind: contribution.scope_kind,
        deployment_id: contribution.deployment_id,
        deployment_revision_id: contribution.deployment_revision_id,
        agent_identity_id: contribution.agent_identity_id,
        agent_target_kind: contribution.agent_target_kind,
        agent_kem_fingerprint_b64: STANDARD.encode(&contribution.agent_kem_fingerprint),
        agent_signing_fingerprint_b64: STANDARD.encode(&contribution.agent_signing_fingerprint),
        allowed_access_levels: &contribution.allowed_access_levels,
        request_nonce: &contribution.request_nonce,
        expires_at_unix_seconds: contribution.expires_at_unix_seconds,
        participant_id: contribution.participant_id,
        role: &contribution.role,
        stage: contribution.stage,
        actor_organization_id: contribution.actor_organization_id,
        actor_user_id: contribution.actor_user_id,
        actor_identity_id: contribution.actor_identity_id,
        contribution_id: contribution.contribution_id,
        decision: contribution.decision,
        mappings: &contribution.mappings,
        vault_grants: &contribution.vault_grants,
        vault_provisioning: contribution.vault_provisioning.as_ref(),
    })
    .map_err(|_| CryptoError::Canonicalization("contribution JSON encode failed"))
}

/// Canonicalize and sign one participant's agent-delegation contribution.
pub fn sign_agent_delegation_contribution(
    signing_private_key: &IdentitySigningPrivateKey,
    contribution: AgentDelegationContribution,
) -> CryptoResult<Vec<u8>> {
    let payload = agent_delegation_contribution_payload(contribution)?;
    Ok(signing::sign(signing_private_key, &payload))
}

fn validate_contribution(contribution: &AgentDelegationContribution) -> CryptoResult<()> {
    if contribution.agent_kem_fingerprint.len() != 32 {
        return Err(CryptoError::Canonicalization(
            "agent KEM fingerprint must be 32 bytes",
        ));
    }
    if contribution.agent_signing_fingerprint.len() != 32 {
        return Err(CryptoError::Canonicalization(
            "agent signing fingerprint must be 32 bytes",
        ));
    }
    match contribution.scope_kind {
        AgentDelegationScopeKind::SecretFields => {
            if contribution.vault_provisioning.is_some()
                || contribution.deployment_id.is_none()
                || contribution.deployment_revision_id.is_none()
                || contribution.agent_target_kind != AgentDelegationTargetKind::Existing
                || contribution.allowed_access_levels != [AgentDelegationAccessLevel::Read]
            {
                return Err(CryptoError::Canonicalization(
                    "invalid secret-field delegation scope",
                ));
            }
        }
        AgentDelegationScopeKind::VaultAccess => {
            if let Some(provisioning) = &contribution.vault_provisioning {
                validate_vault_provisioning(contribution, provisioning)?;
            } else if contribution.deployment_id.is_some()
                || contribution.deployment_revision_id.is_some()
                || contribution.allowed_access_levels.is_empty()
            {
                return Err(CryptoError::Canonicalization(
                    "invalid vault-access delegation scope",
                ));
            }
        }
    }
    if contribution.expires_at_unix_seconds < 0 {
        return Err(CryptoError::Canonicalization(
            "delegation expiry must be non-negative",
        ));
    }
    validate_text(&contribution.request_nonce, "invalid request nonce")?;
    validate_text(&contribution.role, "invalid participant role")?;
    if contribution.mappings.len() > MAX_MAPPINGS {
        return Err(CryptoError::Canonicalization(
            "delegation mappings exceed max length",
        ));
    }
    if contribution.vault_grants.len() > MAX_VAULT_GRANTS {
        return Err(CryptoError::Canonicalization(
            "delegation vault grants exceed max length",
        ));
    }
    for mapping in &contribution.mappings {
        validate_text(&mapping.environment_name, "invalid environment name")?;
        if let Some(group) = &mapping.field_group {
            validate_text(group, "invalid field group")?;
        }
        validate_text(&mapping.field, "invalid mapping field")?;
        if mapping.item_key_wrap.is_empty() || mapping.item_key_wrap.len() > MAX_OPAQUE_WRAP_BYTES {
            return Err(CryptoError::Canonicalization(
                "invalid delegation item key wrap",
            ));
        }
    }
    for grant in &contribution.vault_grants {
        if !contribution
            .allowed_access_levels
            .contains(&grant.access_level)
        {
            return Err(CryptoError::Canonicalization(
                "vault grant access exceeds delegation scope",
            ));
        }
        if grant.wrapped_vault_key.is_empty()
            || grant.wrapped_vault_key.len() > MAX_OPAQUE_WRAP_BYTES
        {
            return Err(CryptoError::Canonicalization(
                "invalid delegation vault key wrap",
            ));
        }
        if grant.granted_signature.is_empty() || grant.granted_signature.len() > MAX_SIGNATURE_BYTES
        {
            return Err(CryptoError::Canonicalization(
                "invalid delegation vault grant signature",
            ));
        }
    }
    Ok(())
}

fn validate_vault_provisioning(
    contribution: &AgentDelegationContribution,
    provisioning: &AgentDelegationVaultProvisioning,
) -> CryptoResult<()> {
    provisioning.binding.validate()?;
    if contribution.deployment_id.is_none()
        || contribution.deployment_revision_id.is_none()
        || contribution.agent_target_kind != AgentDelegationTargetKind::Existing
        || contribution.allowed_access_levels != [AgentDelegationAccessLevel::Write]
        || !contribution.mappings.is_empty()
    {
        return Err(CryptoError::Canonicalization(
            "invalid vault provisioning scope",
        ));
    }
    if contribution.decision == AgentDelegationDecision::Decline {
        if !provisioning.provisioned_vaults.is_empty() || !contribution.vault_grants.is_empty() {
            return Err(CryptoError::Canonicalization(
                "declined vault provisioning has grants",
            ));
        }
        return Ok(());
    }
    let expected_keys: BTreeSet<_> = provisioning.binding.keys.iter().collect();
    let mapped_keys: BTreeSet<_> = provisioning
        .provisioned_vaults
        .iter()
        .map(|v| &v.key)
        .collect();
    let mapped_vaults: BTreeSet<_> = provisioning
        .provisioned_vaults
        .iter()
        .map(|v| v.vault_id)
        .collect();
    let granted_vaults: BTreeSet<_> = contribution
        .vault_grants
        .iter()
        .map(|v| v.vault_id)
        .collect();
    if expected_keys != mapped_keys
        || provisioning.provisioned_vaults.len() != expected_keys.len()
        || mapped_vaults.len() != expected_keys.len()
        || contribution.vault_grants.len() != expected_keys.len()
        || mapped_vaults != granted_vaults
        || contribution
            .vault_grants
            .iter()
            .any(|g| g.access_level != AgentDelegationAccessLevel::Write)
    {
        return Err(CryptoError::Canonicalization(
            "vault provisioning map must match grants",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, message: &'static str) -> CryptoResult<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(CryptoError::Canonicalization(message));
    }
    Ok(())
}

mod base64_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD
            .decode(value.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentitySigningKeypair;

    fn contribution() -> AgentDelegationContribution {
        AgentDelegationContribution {
            request_id: Uuid::from_u128(1),
            result_id: Uuid::from_u128(2),
            destination_organization_id: Uuid::from_u128(3),
            scope_kind: AgentDelegationScopeKind::SecretFields,
            deployment_id: Some(Uuid::from_u128(4)),
            deployment_revision_id: Some(Uuid::from_u128(5)),
            agent_identity_id: Uuid::from_u128(6),
            agent_target_kind: AgentDelegationTargetKind::Existing,
            agent_kem_fingerprint: vec![0xab; 32],
            agent_signing_fingerprint: vec![0xcd; 32],
            allowed_access_levels: vec![AgentDelegationAccessLevel::Read],
            request_nonce: "0123456789abcdef".into(),
            expires_at_unix_seconds: 1_800_000_000,
            participant_id: Uuid::from_u128(7),
            role: "custodian".into(),
            stage: 1,
            actor_organization_id: Uuid::from_u128(8),
            actor_user_id: Uuid::from_u128(9),
            actor_identity_id: Uuid::from_u128(10),
            contribution_id: Uuid::from_u128(11),
            decision: AgentDelegationDecision::Approve,
            vault_provisioning: None,
            mappings: vec![AgentDelegationFieldMapping {
                environment_name: "DB_PASSWORD".into(),
                field_group: Some("database".into()),
                vault_id: Uuid::from_u128(12),
                item_id: Uuid::from_u128(13),
                field: "password".into(),
                item_key_wrap: vec![1, 2, 3],
            }],
            vault_grants: vec![AgentDelegationVaultGrant {
                vault_id: Uuid::from_u128(12),
                access_level: AgentDelegationAccessLevel::Read,
                wrapped_vault_key: vec![4, 5, 6],
                granted_signature: vec![7, 8, 9],
            }],
        }
    }

    #[test]
    fn known_answer_vector_matches_the_passwords_service_layout() {
        let payload = agent_delegation_contribution_payload(contribution()).unwrap();
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            r#"{"domain":"seren-secrets/agent-delegation-policy-contribution","request_id":"00000000-0000-0000-0000-000000000001","result_id":"00000000-0000-0000-0000-000000000002","destination_organization_id":"00000000-0000-0000-0000-000000000003","scope_kind":"secret_fields","deployment_id":"00000000-0000-0000-0000-000000000004","deployment_revision_id":"00000000-0000-0000-0000-000000000005","agent_identity_id":"00000000-0000-0000-0000-000000000006","agent_target_kind":"existing","agent_kem_fingerprint_b64":"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=","agent_signing_fingerprint_b64":"zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0=","allowed_access_levels":["read"],"request_nonce":"0123456789abcdef","expires_at_unix_seconds":1800000000,"participant_id":"00000000-0000-0000-0000-000000000007","role":"custodian","stage":1,"actor_organization_id":"00000000-0000-0000-0000-000000000008","actor_user_id":"00000000-0000-0000-0000-000000000009","actor_identity_id":"00000000-0000-0000-0000-00000000000a","contribution_id":"00000000-0000-0000-0000-00000000000b","decision":"approve","mappings":[{"environment_name":"DB_PASSWORD","field_group":"database","vault_id":"00000000-0000-0000-0000-00000000000c","item_id":"00000000-0000-0000-0000-00000000000d","field":"password","item_key_wrap":"AQID"}],"vault_grants":[{"vault_id":"00000000-0000-0000-0000-00000000000c","access_level":"read","wrapped_vault_key":"BAUG","granted_signature":"BwgJ"}]}"#,
        );
    }

    #[test]
    fn canonicalizes_order_and_rejects_duplicates() {
        let mut input = contribution();
        let mut second = input.mappings[0].clone();
        second.environment_name = "API_TOKEN".into();
        second.item_id = Uuid::from_u128(14);
        input.mappings.insert(0, second);
        let payload = agent_delegation_contribution_payload(input).unwrap();
        let text = String::from_utf8(payload).unwrap();
        assert!(text.find("API_TOKEN").unwrap() < text.find("DB_PASSWORD").unwrap());

        let mut duplicate = contribution();
        duplicate.mappings.push(duplicate.mappings[0].clone());
        assert!(agent_delegation_contribution_payload(duplicate).is_err());
    }

    #[test]
    fn contribution_signature_verifies_over_the_shared_payload() {
        let signing = IdentitySigningKeypair::generate();
        let input = contribution();
        let payload = agent_delegation_contribution_payload(input.clone()).unwrap();
        let signature = sign_agent_delegation_contribution(&signing.private, input).unwrap();
        signing::verify(&signing.public, &payload, &signature).unwrap();
    }

    fn provisioning() -> AgentDelegationContribution {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/provisioning-delegation.json"
        ))
        .unwrap()
    }

    #[test]
    fn provisioning_known_answer_and_legacy_serde_omit_extension() {
        for (input, expected) in [
            (
                include_str!("../../tests/fixtures/legacy-delegation.json"),
                include_str!("../../tests/fixtures/legacy-delegation.payload.json"),
            ),
            (
                include_str!("../../tests/fixtures/provisioning-delegation.json"),
                include_str!("../../tests/fixtures/provisioning-delegation.payload.json"),
            ),
        ] {
            let input: AgentDelegationContribution = serde_json::from_str(input).unwrap();
            assert_eq!(
                agent_delegation_contribution_payload(input).unwrap(),
                expected.trim_end().as_bytes()
            );
        }
        assert!(
            !serde_json::to_string(&contribution())
                .unwrap()
                .contains("vault_provisioning")
        );
    }

    #[test]
    fn provisioning_map_is_order_independent_and_decline_has_no_grants() {
        let mut input = provisioning();
        let mut grant = input.vault_grants[0].clone();
        grant.vault_id = Uuid::from_u128(30);
        input.vault_grants.push(grant);
        let ext = input.vault_provisioning.as_mut().unwrap();
        ext.binding.keys.push("another-source".into());
        ext.binding.vault_count = 2;
        ext.provisioned_vaults.push(ProvisionedVault {
            key: "another-source".into(),
            vault_id: Uuid::from_u128(30),
            adopted: false,
        });
        let expected = agent_delegation_contribution_payload(input.clone()).unwrap();
        input.vault_grants.reverse();
        input
            .vault_provisioning
            .as_mut()
            .unwrap()
            .binding
            .keys
            .reverse();
        input
            .vault_provisioning
            .as_mut()
            .unwrap()
            .provisioned_vaults
            .reverse();
        assert_eq!(
            agent_delegation_contribution_payload(input.clone()).unwrap(),
            expected
        );
        input.decision = AgentDelegationDecision::Decline;
        assert!(agent_delegation_contribution_payload(input.clone()).is_err());
        input.vault_grants.clear();
        input
            .vault_provisioning
            .as_mut()
            .unwrap()
            .provisioned_vaults
            .clear();
        assert!(agent_delegation_contribution_payload(input).is_ok());
    }

    #[test]
    fn rejects_malformed_provisioning_and_preserves_generic_scope_guards() {
        let mutations: &[fn(&mut AgentDelegationContribution)] = &[
            |c| c.vault_provisioning.as_mut().unwrap().binding.keys.clear(),
            |c| c.vault_provisioning.as_mut().unwrap().binding.keys[0].clear(),
            |c| c.vault_provisioning.as_mut().unwrap().binding.keys[0] = " ".into(),
            |c| {
                let b = &mut c.vault_provisioning.as_mut().unwrap().binding;
                b.keys.push(b.keys[0].clone());
                b.vault_count = 2;
            },
            |c| c.vault_provisioning.as_mut().unwrap().binding.vault_count = 2,
            |c| {
                c.vault_provisioning
                    .as_mut()
                    .unwrap()
                    .binding
                    .payload_digest = "bad".into()
            },
            |c| c.vault_provisioning.as_mut().unwrap().provisioned_vaults[0].key = "unknown".into(),
            |c| {
                let p = c.vault_provisioning.as_mut().unwrap();
                p.provisioned_vaults.push(p.provisioned_vaults[0].clone());
            },
            |c| {
                c.vault_provisioning.as_mut().unwrap().provisioned_vaults[0].vault_id =
                    Uuid::from_u128(999)
            },
            |c| c.vault_grants.clear(),
            |c| c.vault_grants.push(c.vault_grants[0].clone()),
            |c| c.vault_grants[0].access_level = AgentDelegationAccessLevel::Read,
            |c| c.allowed_access_levels = vec![AgentDelegationAccessLevel::Admin],
            |c| c.deployment_id = None,
            |c| c.deployment_revision_id = None,
            |c| c.agent_target_kind = AgentDelegationTargetKind::Bootstrap,
            |c| c.scope_kind = AgentDelegationScopeKind::SecretFields,
            |c| c.mappings = contribution().mappings,
            |c| c.vault_provisioning = None,
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut input = provisioning();
            mutate(&mut input);
            assert!(
                agent_delegation_contribution_payload(input).is_err(),
                "mutation {i}"
            );
        }
        let mut wire = serde_json::to_value(provisioning()).unwrap();
        wire["vault_provisioning"]["grant_lifetime"] = "forever".into();
        assert!(serde_json::from_value::<AgentDelegationContribution>(wire).is_err());
        let mut generic = provisioning();
        generic.vault_provisioning = None;
        generic.deployment_id = None;
        generic.deployment_revision_id = None;
        assert!(agent_delegation_contribution_payload(generic).is_ok());
    }

    #[test]
    fn signature_binds_provisioning_map_adoption_and_existing_context() {
        let signing = IdentitySigningKeypair::generate();
        let input = provisioning();
        let signature =
            sign_agent_delegation_contribution(&signing.private, input.clone()).unwrap();
        let payload = agent_delegation_contribution_payload(input.clone()).unwrap();
        signing::verify(&signing.public, &payload, &signature).unwrap();
        let mutations: &[fn(&mut AgentDelegationContribution)] = &[
            |c| {
                let p = c.vault_provisioning.as_mut().unwrap();
                p.binding.keys[0] = "replacement".into();
                p.provisioned_vaults[0].key = "replacement".into();
            },
            |c| {
                c.vault_grants[0].vault_id = Uuid::from_u128(999);
                c.vault_provisioning.as_mut().unwrap().provisioned_vaults[0].vault_id =
                    Uuid::from_u128(999);
            },
            |c| c.vault_provisioning.as_mut().unwrap().provisioned_vaults[0].adopted = false,
            |c| {
                c.vault_provisioning
                    .as_mut()
                    .unwrap()
                    .binding
                    .payload_digest = "cd".repeat(32)
            },
            |c| c.deployment_id = Some(Uuid::from_u128(999)),
            |c| c.deployment_revision_id = Some(Uuid::from_u128(999)),
            |c| c.vault_grants[0].wrapped_vault_key[0] ^= 1,
            |c| c.vault_grants[0].granted_signature[0] ^= 1,
            |c| c.agent_identity_id = Uuid::from_u128(999),
            |c| c.expires_at_unix_seconds += 1,
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut changed = input.clone();
            mutate(&mut changed);
            let changed = agent_delegation_contribution_payload(changed).unwrap();
            assert!(
                signing::verify(&signing.public, &changed, &signature).is_err(),
                "mutation {i}"
            );
        }
    }
}

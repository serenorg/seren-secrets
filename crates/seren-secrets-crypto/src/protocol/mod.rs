//! High-level protocol flows composed from the primitive modules.

pub mod account;
pub mod account_secrets_update;
pub mod agent_delegation_policy;
pub mod approval;
pub mod attachment;
pub mod blind_index;
pub mod item;
pub mod membership_grant;
pub mod recovery;
pub mod recovery_proof;
pub mod resolve;
pub mod vault;

pub use account::{AccountSecrets, account_setup, change_master_password, unlock_account};
pub use account_secrets_update::{
    AccountSecretsUpdateProof, build_update_proof, canonical_json_bytes,
    digest_account_secrets_blob, verify_update_proof, verify_update_proof_fresh,
};
pub use agent_delegation_policy::{
    AGENT_DELEGATION_CONTRIBUTION_DOMAIN, AgentDelegationAccessLevel, AgentDelegationContribution,
    AgentDelegationDecision, AgentDelegationFieldMapping, AgentDelegationScopeKind,
    AgentDelegationTargetKind, AgentDelegationVaultGrant, agent_delegation_contribution_payload,
    sign_agent_delegation_contribution,
};
pub use approval::{ApprovalRequest, build_approval_request, verify_approval_request};
pub use blind_index::blind_index_title;
pub use item::ItemContent;
pub use membership_grant::{
    membership_grant_signing_bytes, sign_membership_grant, verify_membership_grant,
};
pub use recovery::{recover_with_recovery_key, regenerate_recovery_key};
pub use recovery_proof::{RecoveryProof, build_recovery_proof, verify_recovery_proof};
pub use resolve::{ResolveRequest, build_resolve_signature, verify_resolve_signature};
pub use vault::{generate_vault_key, unwrap_vault_key, wrap_vault_key_for_identity};

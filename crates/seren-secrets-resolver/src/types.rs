use async_trait::async_trait;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ResolverError;

/// The contract every secret resolver implements.
///
/// Hosts may compose E2EE secret resolution with server-trusted secret
/// sources. `ResolvedSecret::source` keeps those trust paths explicit.
#[async_trait]
pub trait AgentSecretResolver: Send + Sync {
    async fn resolve(
        &self,
        uri: &str,
        ctx: &ResolutionContext,
    ) -> Result<ResolvedSecret, ResolverError>;
}

/// Per-request context. The resolver may use these fields to pick the right
/// HTTP credentials, the right agent identity for signing, and to attach
/// audit metadata.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    /// The agent identity making the call, when the caller is an agent.
    pub agent_identity_id: Option<Uuid>,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    /// Optional caller-supplied correlation id for audit/event lineage.
    pub correlation_id: Option<Uuid>,
}

impl ResolutionContext {
    pub fn for_agent(agent_identity_id: Uuid, organization_id: Uuid, user_id: Uuid) -> Self {
        Self {
            agent_identity_id: Some(agent_identity_id),
            organization_id,
            user_id,
            correlation_id: None,
        }
    }

    pub fn for_user(organization_id: Uuid, user_id: Uuid) -> Self {
        Self {
            agent_identity_id: None,
            organization_id,
            user_id,
            correlation_id: None,
        }
    }

    pub fn with_correlation_id(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }
}

pub struct ResolvedSecret {
    /// Plaintext field value. Callers must never log or persist it.
    /// `Zeroizing<String>` wipes the buffer on drop.
    pub plaintext: Zeroizing<String>,
    /// The field the caller asked for, e.g. "password", "username",
    /// "primary_value", "secret_base32".
    pub field_name: String,
    /// Which trust path produced this value.
    pub source: SecretSource,
}

impl std::fmt::Debug for ResolvedSecret {
    // Redact plaintext in accidental debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSecret")
            .field("plaintext", &"<redacted>")
            .field("field_name", &self.field_name)
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// Server-trusted organization-scoped source.
    OrgSecret,
    /// Server-trusted user-scoped source.
    UserSecret,
    /// End-to-end-encrypted source decrypted in this process.
    SerenSecrets,
}

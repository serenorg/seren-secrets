//! Host-side resolver for `seren-secrets://` references plus the vault
//! management client.
//!
//! Sits above the pure-crypto crate (`seren-secrets-crypto`, which has no
//! I/O) and provides the network-bound piece an agent runtime needs: signed
//! resolve requests, an HTTP client, and the unwrap-and-extract path that
//! turns the server's ciphertext response into plaintext for the approved
//! caller.
//!
//! `seren-secrets://...` is end-to-end-encrypted: the server returns
//! ciphertext plus the caller's wrapped vault key, and this process performs
//! the unwrap with the agent identity's KEM private key. The
//! [`AgentSecretResolver`] trait and [`SecretSource`] stay a generic contract so a host can
//! compose this E2EE resolver with its own server-trusted resolvers (e.g.
//! `org-secret://` / `user-secret://`), which live in the consuming agent
//! runtime rather than here.

pub mod error;
mod http;
pub mod seren_secrets;
pub mod types;
pub mod vault;

pub use error::ResolverError;
pub use seren_secrets::{SerenSecretsResolver, SerenSecretsResolverConfig};
pub use types::{AgentSecretResolver, ResolutionContext, ResolvedSecret, SecretSource};
pub use vault::{
    AgentInfo, AgentVaultGrantInfo, ApprovalStatus, VaultClient, VaultClientConfig, VaultKeySource,
    canonical_create_agent_bytes, create_agent_identity, fetch_master_password_key_source,
    grant_membership, list_agents, revoke_agent_identity, revoke_membership,
};

pub type ResolverResult<T> = Result<T, ResolverError>;

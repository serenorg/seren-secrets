use std::borrow::Cow;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use seren_secrets_crypto::kdf::KdfParams;
use seren_secrets_crypto::keys::{
    IdentityKemPrivateKey, IdentityKemPublicKey, IdentitySigningPrivateKey,
    IdentitySigningPublicKey, ItemContentKey, VaultKey,
};
use seren_secrets_crypto::protocol::account::{AccountSecrets, unlock_account};
use seren_secrets_crypto::protocol::item::{
    ItemContent, decrypt_item_with_content_key, decrypt_metadata_json, decrypt_tags, decrypt_title,
    encrypt_item_with_content_key, encrypt_metadata_json, encrypt_tags, encrypt_title,
    generate_item_content_key, unwrap_item_content_key, wrap_item_content_key,
};
use seren_secrets_crypto::protocol::vault::{
    decrypt_vault_name, unwrap_vault_key, wrap_vault_key_for_identity,
};

use crate::error::{ResolverError, truncate_error_body};
use crate::http::{
    MAX_ERROR_BODY, MAX_GATEWAY_BODY, read_capped, read_capped_text, validate_base_url,
};

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------
//
// All ciphertext/wrapped-key fields arrive as base64 strings on the wire
// (the upstream service uses `bytes_b64`/`option_bytes_b64` + a schema
// override). We keep them as `String` here so the client can forward them to
// the crypto crate after decoding, without forcing an extra allocation on
// every response.
//
// Fields the client does not currently consume are silently dropped via
// `#[serde(default)]`.

/// Aggregate response from `GET /sync`.
#[derive(Debug, Deserialize)]
pub struct SyncResponse {
    pub vaults: Vec<VaultRecord>,
    pub item_overviews: Vec<ItemSummary>,
    /// Dropped; present for forward-compatibility.
    #[serde(default)]
    pub identities: Vec<serde_json::Value>,
    /// Dropped; present for forward-compatibility.
    #[serde(default)]
    pub memberships: Vec<serde_json::Value>,
    /// RFC3339 server clock; used to calibrate resolve-signature freshness.
    #[serde(default)]
    pub server_time: String,
}

/// Vault record as returned by `/sync` and `/vaults/{id}`.
///
/// `name_ciphertext` and `wrapped_vault_key` are base64 strings on the wire.
#[derive(Debug, Deserialize)]
pub struct VaultRecord {
    pub vault_id: Uuid,
    /// Base64-encoded ciphertext of the vault name.
    pub name_ciphertext: String,
    /// Base64-encoded ciphertext of the vault description (optional).
    #[serde(default)]
    pub description_ciphertext: Option<String>,
    /// Monotone counter incremented on every key rotation.
    #[serde(default)]
    pub vault_key_version: Option<i32>,
    /// Caller's vault key, sealed under the caller's KEM public key.
    /// Present when the server includes a membership record for this caller.
    #[serde(default)]
    pub wrapped_vault_key: Option<String>,
    #[serde(default)]
    pub requires_approval: serde_json::Value,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Item overview (no body) from `/sync` and item listing endpoints.
#[derive(Debug, Deserialize)]
pub struct ItemSummary {
    pub item_id: Uuid,
    pub vault_id: Uuid,
    /// Base64-encoded ciphertext of the item title.
    pub title_ciphertext: String,
    /// Base64-encoded ciphertext of the item tags (optional).
    #[serde(default)]
    pub tags_ciphertext: Option<String>,
    /// Base64-encoded metadata ciphertext.
    pub metadata_ciphertext: String,
    /// Base64-encoded BLAKE3 blind index of the plaintext title.
    pub title_blind_index: String,
    #[serde(default)]
    pub updated_at: String,
}

/// Full item record from `GET /vaults/{vault_id}/items/{item_id}`.
#[derive(Debug, Deserialize)]
pub struct ItemRecord {
    pub item_id: Uuid,
    pub vault_id: Uuid,
    /// Base64-encoded ciphertext of the item title.
    pub title_ciphertext: String,
    /// Base64-encoded ciphertext of the item body (sealed under the content key).
    pub content_ciphertext: String,
    /// Base64-encoded ciphertext of the item tags (optional).
    #[serde(default)]
    pub tags_ciphertext: Option<String>,
    /// Base64-encoded BLAKE3 blind index of the plaintext title.
    pub title_blind_index: String,
    /// Per-item content key wrapped under the vault key.
    pub content_key_wrap: String,
    /// Base64-encoded metadata ciphertext.
    pub metadata_ciphertext: String,
    #[serde(default)]
    pub sensitive: bool,
    /// Vault key version under which these ciphertexts were sealed.
    #[serde(default)]
    pub vault_key_version: Option<i32>,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub archived_at: Option<String>,
    #[serde(default)]
    pub trashed_at: Option<String>,
}

/// Wire shape from `GET /account/secrets` (inner payload after envelope unwrap).
#[derive(serde::Deserialize)]
struct AccountSecretsRecord {
    kdf_params: serde_json::Value,
    recovery_kdf_params: serde_json::Value,
    account_key_wrap: String,
    account_kem_private_wrap: String,
    account_signing_private_wrap: String,
    recovery_key_wrap: String,
}

/// Wire shape from `GET /identities/me` (inner payload after envelope unwrap).
#[derive(serde::Deserialize)]
struct IdentityRecord {
    kem_public_key: String,
    signing_public_key: String,
}

/// Body for `POST /vaults/{vault_id}/items`.
#[derive(Debug, Serialize)]
pub struct CreateItemRequest {
    pub item_id: Uuid,
    /// Base64-encoded ciphertext of the item title.
    pub title_ciphertext: String,
    /// Base64-encoded ciphertext of the item body.
    pub content_ciphertext: String,
    /// Base64-encoded ciphertext of the item tags (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags_ciphertext: Option<String>,
    /// Base64-encoded BLAKE3 blind index of the plaintext title.
    pub title_blind_index: String,
    /// Per-item content key wrapped under the vault key.
    pub content_key_wrap: String,
    /// Base64-encoded metadata ciphertext.
    pub metadata_ciphertext: String,
    pub sensitive: bool,
    /// Vault key version the client sealed under; server rejects on mismatch (409).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapping_key_version: Option<i32>,
}

/// Body for `PATCH /vaults/{vault_id}/items/{item_id}`.
///
/// Like `CreateItemRequest` but without `item_id` (that's a path parameter).
#[derive(Debug, Serialize)]
pub struct UpdateItemRequest {
    /// Base64-encoded ciphertext of the item title.
    pub title_ciphertext: String,
    /// Base64-encoded ciphertext of the item body.
    pub content_ciphertext: String,
    /// Base64-encoded ciphertext of the item tags (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags_ciphertext: Option<String>,
    /// Base64-encoded BLAKE3 blind index of the plaintext title.
    pub title_blind_index: String,
    /// Per-item content key wrapped under the vault key.
    pub content_key_wrap: String,
    /// Base64-encoded metadata ciphertext.
    pub metadata_ciphertext: String,
    /// Required on every update; the server uses it to enforce rotation-race safety.
    pub sensitive: bool,
    /// Vault key version the client sealed under; server rejects on mismatch (409).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapping_key_version: Option<i32>,
}

// ---------------------------------------------------------------------------
// Decrypted view types
// ---------------------------------------------------------------------------

/// Vault record after the vault key has been unwrapped and the name decrypted.
// VaultKey has a custom Debug that redacts the key material; derive here is safe.
#[derive(Debug)]
pub struct DecryptedVault {
    pub vault_id: Uuid,
    pub name: String,
    pub key: VaultKey,
    pub key_version: i32,
}

/// Item record after all ciphertext fields have been decrypted.
///
/// Full-item reads return plaintext fields. Callers must treat the returned
/// value as sensitive and avoid logging or persisting it.
pub struct DecryptedItem {
    pub item_id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub sensitive: bool,
    pub content: ItemContent,
    pub metadata_json: String,
}

// ---------------------------------------------------------------------------
// Pure (no-I/O) build and decrypt helpers
// ---------------------------------------------------------------------------

/// Decode a base64 string into bytes, tagging the field name in errors.
fn b64_decode(s: &str, field: &'static str) -> Result<Vec<u8>, ResolverError> {
    B64.decode(s.as_bytes())
        .map_err(|_| ResolverError::Malformed(field))
}

/// Assemble an `AccountSecrets` from the two wire records returned by the gateway.
///
/// Parses the KDF param JSON objects, decodes the base64 wrap fields, and
/// constructs the public key newtypes. All failure paths produce a `Malformed`
/// error referencing the specific field so callers can diagnose a schema drift.
fn assemble_account_secrets(
    secrets: AccountSecretsRecord,
    identity: IdentityRecord,
) -> Result<AccountSecrets, ResolverError> {
    let kdf_params: KdfParams = serde_json::from_value(secrets.kdf_params)
        .map_err(|_| ResolverError::Malformed("kdf_params"))?;
    let recovery_kdf_params: KdfParams = serde_json::from_value(secrets.recovery_kdf_params)
        .map_err(|_| ResolverError::Malformed("recovery_kdf_params"))?;

    let account_key_wrap = b64_decode(&secrets.account_key_wrap, "account_key_wrap")?;
    let account_kem_private_wrap = b64_decode(
        &secrets.account_kem_private_wrap,
        "account_kem_private_wrap",
    )?;
    let account_signing_private_wrap = b64_decode(
        &secrets.account_signing_private_wrap,
        "account_signing_private_wrap",
    )?;
    let recovery_key_wrap = b64_decode(&secrets.recovery_key_wrap, "recovery_key_wrap")?;

    let kem_public_key =
        IdentityKemPublicKey::from_slice(&b64_decode(&identity.kem_public_key, "kem_public_key")?)
            .map_err(|_| ResolverError::Malformed("kem_public_key length"))?;
    let signing_public_key = IdentitySigningPublicKey::from_slice(&b64_decode(
        &identity.signing_public_key,
        "signing_public_key",
    )?)
    .map_err(|_| ResolverError::Malformed("signing_public_key length"))?;

    Ok(AccountSecrets {
        kdf_params,
        recovery_kdf_params,
        account_key_wrap,
        account_kem_private_wrap,
        account_signing_private_wrap,
        recovery_key_wrap,
        kem_public_key,
        signing_public_key,
    })
}

/// Derive the `item_kind` string used in the metadata JSON from the content variant.
fn item_kind_str(content: &ItemContent) -> &'static str {
    match content {
        ItemContent::Login(_) => "login",
        ItemContent::SecureNote(_) => "secure_note",
        ItemContent::ApiCredential(_) => "api_credential",
        ItemContent::Card(_) => "card",
        ItemContent::Identity(_) => "identity",
        ItemContent::Document(_) => "document",
        ItemContent::SshKey(_) => "ssh_key",
        ItemContent::Server(_) => "server",
        ItemContent::Database(_) => "database",
        ItemContent::BankAccount(_) => "bank_account",
        ItemContent::Passport(_) => "passport",
        ItemContent::DriverLicense(_) => "driver_license",
        ItemContent::CryptoWallet(_) => "crypto_wallet",
    }
}

/// Build a `CreateItemRequest` from plaintext fields. Pure: no I/O, no `&self`.
fn build_create_request(
    vault_key: &VaultKey,
    item_id: Uuid,
    content: &ItemContent,
    title: &str,
    tags: &[String],
    sensitive: bool,
    version: i32,
) -> Result<CreateItemRequest, ResolverError> {
    let content_key = generate_item_content_key();

    let title_ct = encrypt_title(vault_key, item_id.as_bytes(), title);
    let content_ct = encrypt_item_with_content_key(&content_key, item_id.as_bytes(), content)?;
    let tags_ct = if tags.is_empty() {
        None
    } else {
        Some(encrypt_tags(vault_key, item_id.as_bytes(), tags)?)
    };
    let ck_wrap = wrap_item_content_key(vault_key, item_id.as_bytes(), &content_key);

    let item_kind = item_kind_str(content);
    let metadata_json = format!(
        r#"{{"item_kind":"{item_kind}","favorite":false,"sensitive":{sensitive},"reprompt":false}}"#
    );
    let metadata_ct = encrypt_metadata_json(vault_key, item_id.as_bytes(), &metadata_json);

    Ok(CreateItemRequest {
        item_id,
        title_ciphertext: B64.encode(&title_ct),
        content_ciphertext: B64.encode(&content_ct),
        tags_ciphertext: tags_ct.map(|t| B64.encode(&t)),
        title_blind_index: String::new(),
        content_key_wrap: B64.encode(&ck_wrap),
        metadata_ciphertext: B64.encode(&metadata_ct),
        sensitive,
        wrapping_key_version: Some(version),
    })
}

/// Parse the `favorite` and `reprompt` flags from an item's decrypted metadata
/// JSON, defaulting to false when the field is absent or the JSON is malformed.
///
/// Updates rebuild metadata, so unchanged flags must be carried forward.
fn metadata_flags(metadata_json: &str) -> (bool, bool) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(metadata_json) else {
        return (false, false);
    };
    let favorite = value
        .get("favorite")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let reprompt = value
        .get("reprompt")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    (favorite, reprompt)
}

/// Build an `UpdateItemRequest` from plaintext fields using a pre-existing content key.
///
/// The caller passes the already-unwrapped content key and the original wrap.
/// Body edits re-encrypt content but do not change `content_key_wrap`.
///
/// `title_blind_index` is empty until the transport supports a real derivation.
/// Optimistic concurrency can be added once the transport exposes ETag headers.
#[allow(clippy::too_many_arguments)]
fn build_update_request(
    vault_key: &VaultKey,
    item_id: Uuid,
    content_key: &ItemContentKey,
    content_key_wrap_b64: &str,
    content: &ItemContent,
    title: &str,
    tags: &[String],
    sensitive: bool,
    favorite: bool,
    reprompt: bool,
    version: i32,
) -> Result<UpdateItemRequest, ResolverError> {
    let title_ct = encrypt_title(vault_key, item_id.as_bytes(), title);
    let content_ct = encrypt_item_with_content_key(content_key, item_id.as_bytes(), content)?;
    let tags_ct = if tags.is_empty() {
        None
    } else {
        Some(encrypt_tags(vault_key, item_id.as_bytes(), tags)?)
    };

    let item_kind = item_kind_str(content);
    let metadata_json = format!(
        r#"{{"item_kind":"{item_kind}","favorite":{favorite},"sensitive":{sensitive},"reprompt":{reprompt}}}"#
    );
    let metadata_ct = encrypt_metadata_json(vault_key, item_id.as_bytes(), &metadata_json);

    Ok(UpdateItemRequest {
        title_ciphertext: B64.encode(&title_ct),
        content_ciphertext: B64.encode(&content_ct),
        tags_ciphertext: tags_ct.map(|t| B64.encode(&t)),
        title_blind_index: String::new(),
        // Invariant: content_key_wrap is passed through unchanged. The server
        // stores opaque wrap bytes; re-encryption of the body does not alter them.
        content_key_wrap: content_key_wrap_b64.to_string(),
        metadata_ciphertext: B64.encode(&metadata_ct),
        sensitive,
        wrapping_key_version: Some(version),
    })
}

/// Reject an item record whose ids do not match what the caller requested.
///
/// The server is untrusted: when we ask for `(vault_id, item_id)` it could
/// answer with a different item the caller is also entitled to. Every item AAD
/// is derived from the requested id, so a swap also fails to decrypt, but we
/// reject explicitly here so the failure is unambiguous and so `vault_id`
/// (which the item AADs do not bind) is checked too.
fn ensure_record_matches(
    expected_vault_id: Uuid,
    expected_item_id: Uuid,
    rec: &ItemRecord,
) -> Result<(), ResolverError> {
    if rec.item_id != expected_item_id || rec.vault_id != expected_vault_id {
        return Err(ResolverError::ResponseMismatch);
    }
    Ok(())
}

/// Decrypt a full `ItemRecord` into a `DecryptedItem`. Pure: no I/O, no `&self`.
fn decrypt_item_record(
    vault_key: &VaultKey,
    expected_vault_id: Uuid,
    expected_item_id: Uuid,
    rec: &ItemRecord,
) -> Result<DecryptedItem, ResolverError> {
    ensure_record_matches(expected_vault_id, expected_item_id, rec)?;
    // Bind every AAD to the id the caller requested (now equal to rec.item_id),
    // so a server that swaps in another item's ciphertext also fails to decrypt.
    let item_id = expected_item_id;

    let ck_wrap_bytes = b64_decode(&rec.content_key_wrap, "content_key_wrap")?;
    let content_ct_bytes = b64_decode(&rec.content_ciphertext, "content_ciphertext")?;
    let title_ct_bytes = b64_decode(&rec.title_ciphertext, "title_ciphertext")?;
    let metadata_ct_bytes = b64_decode(&rec.metadata_ciphertext, "metadata_ciphertext")?;

    let content_key = unwrap_item_content_key(vault_key, item_id.as_bytes(), &ck_wrap_bytes)?;
    let content =
        decrypt_item_with_content_key(&content_key, item_id.as_bytes(), &content_ct_bytes)?;
    let title = decrypt_title(vault_key, item_id.as_bytes(), &title_ct_bytes)?;
    let tags = match &rec.tags_ciphertext {
        Some(tc) => {
            let tc_bytes = b64_decode(tc, "tags_ciphertext")?;
            decrypt_tags(vault_key, item_id.as_bytes(), &tc_bytes)?
        }
        None => Vec::new(),
    };
    let metadata_json = decrypt_metadata_json(vault_key, item_id.as_bytes(), &metadata_ct_bytes)?;

    Ok(DecryptedItem {
        item_id,
        title,
        tags,
        sensitive: rec.sensitive,
        content: content.into_inner(),
        metadata_json,
    })
}

/// Unwrap the vault key and decrypt the vault name from a `VaultRecord`.
/// Pure: no I/O, no `&self`.
fn decrypt_vault_record(
    kem_private: &IdentityKemPrivateKey,
    rec: &VaultRecord,
) -> Result<DecryptedVault, ResolverError> {
    let wrapped = rec
        .wrapped_vault_key
        .as_deref()
        .ok_or(ResolverError::Malformed("missing wrapped_vault_key"))?;
    let wrapped_bytes = b64_decode(wrapped, "wrapped_vault_key")?;
    let vault_key = unwrap_vault_key(kem_private, &wrapped_bytes)?;

    let name_ct_bytes = b64_decode(&rec.name_ciphertext, "name_ciphertext")?;
    let name = decrypt_vault_name(&vault_key, rec.vault_id.as_bytes(), &name_ct_bytes)
        .unwrap_or_else(|_| "(unreadable vault)".to_string());

    Ok(DecryptedVault {
        vault_id: rec.vault_id,
        name,
        key_version: rec.vault_key_version.unwrap_or(1),
        key: vault_key,
    })
}

// ---------------------------------------------------------------------------
// VaultKeySource
// ---------------------------------------------------------------------------

/// Identity-agnostic source for the KEM private key used to unwrap vault keys.
///
/// - `AgentKey` - the caller already holds an `IdentityKemPrivateKey` (e.g.
///   loaded from a KMS or an agent keystore at startup).
/// - `MasterPassword` - the caller holds `AccountSecrets` from the server plus
///   the master password; `kem_private` performs the Argon2id + XChaCha20
///   unwrap inline.
pub enum VaultKeySource {
    MasterPassword {
        secrets: Box<AccountSecrets>,
        master_password: Zeroizing<Vec<u8>>,
    },
    AgentKey {
        kem_private: IdentityKemPrivateKey,
    },
}

impl VaultKeySource {
    /// Return the KEM private key, deriving it on the fly if needed.
    ///
    /// For `AgentKey` this is a cheap borrow. For `MasterPassword` it runs the
    /// full Argon2id + XChaCha20 unlock path and returns an owned key.
    pub fn kem_private(&self) -> Result<Cow<'_, IdentityKemPrivateKey>, ResolverError> {
        match self {
            Self::AgentKey { kem_private } => Ok(Cow::Borrowed(kem_private)),
            Self::MasterPassword {
                secrets,
                master_password,
            } => {
                let unlocked = unlock_account(master_password, secrets)?;
                Ok(Cow::Owned(unlocked.kem_private))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VaultClient
// ---------------------------------------------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for a `VaultClient`.
pub struct VaultClientConfig {
    /// Base URL of the secrets API endpoint.
    pub base_url: String,
    /// Bearer token used by the gateway to authenticate the caller.
    pub bearer_token: String,
    /// Source of the KEM private key for vault-key unwrapping.
    pub key_source: VaultKeySource,
}

/// Full vault management client for the secrets API endpoint.
///
/// Requests go to `{base_url}{path}`. If the endpoint returns a metered
/// envelope, `call` unwraps it and returns the inner payload value.
pub struct VaultClient {
    http: reqwest::Client,
    base_url: String,
    bearer: Zeroizing<String>,
    key_source: VaultKeySource,
}

impl VaultClient {
    /// Build a `VaultClient` from `config`.
    ///
    /// Mirrors `SerenSecretsResolver::new`: constructs a reqwest client with
    /// connect/request timeouts and trims the trailing slash from `base_url`.
    pub fn new(config: VaultClientConfig) -> Result<Self, ResolverError> {
        validate_base_url(&config.base_url)?;
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(ResolverError::transport)?;

        Ok(Self {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            bearer: Zeroizing::new(config.bearer_token),
            key_source: config.key_source,
        })
    }

    /// Issue an authenticated GET/POST/PATCH through the gateway and return
    /// the unwrapped inner payload as a `serde_json::Value`.
    ///
    /// The gateway envelope is:
    /// `{ "data": { "status": 200, ..., "body": { "data": <T> } } }`
    /// so after unwrapping the metered envelope and the DataResponse layer,
    /// the result is the bare `<T>` value.
    pub(crate) async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ResolverError> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.http.request(method, &url).bearer_auth(&*self.bearer);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(ResolverError::transport)?;

        let status = resp.status();
        if !status.is_success() {
            let raw = read_capped_text(resp, MAX_ERROR_BODY).await;
            // Preserve ApprovalRequired instead of flattening it into 403.
            if status.as_u16() == 403
                && let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw)
                && let Some(request_id) = crate::error::approval_request_id_from_value(&value)
            {
                return Err(ResolverError::ApprovalRequired { request_id });
            }
            return Err(ResolverError::ServerError {
                status: status.as_u16(),
                body: truncate_error_body(raw),
            });
        }

        let body = read_capped(resp, MAX_GATEWAY_BODY).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| ResolverError::Malformed("response body"))?;

        unwrap_metered(value)
    }

    /// Create an item in a vault. Encrypts the content, title, tags, and
    /// metadata locally, then POSTs the ciphertext to the server.
    /// Returns the new `item_id` on success.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_item(
        &self,
        vault_id: Uuid,
        vault_key: &VaultKey,
        content: ItemContent,
        title: &str,
        tags: &[String],
        sensitive: bool,
        version: i32,
    ) -> Result<Uuid, ResolverError> {
        let item_id = Uuid::new_v4();
        let req = build_create_request(
            vault_key, item_id, &content, title, tags, sensitive, version,
        )?;
        // Do not hold plaintext content across the network await.
        drop(content);
        self.call(
            reqwest::Method::POST,
            &format!("/vaults/{vault_id}/items"),
            Some(
                serde_json::to_value(req)
                    .map_err(|_| ResolverError::Malformed("serialize request"))?,
            ),
        )
        .await?;
        Ok(item_id)
    }

    /// Fetch and decrypt all vaults the caller has access to.
    pub async fn list_vaults(&self) -> Result<Vec<DecryptedVault>, ResolverError> {
        let kem = self.key_source.kem_private()?;
        let v = self.call(reqwest::Method::GET, "/sync", None).await?;
        let sync: SyncResponse =
            serde_json::from_value(v).map_err(|_| ResolverError::Malformed("sync"))?;
        sync.vaults
            .iter()
            .filter(|r| r.wrapped_vault_key.is_some())
            .map(|record| decrypt_vault_record(&kem, record))
            .collect()
    }

    /// List the items in a vault, returning `(item_id, decrypted title)` pairs.
    pub async fn list_items(
        &self,
        vault_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<Vec<(Uuid, String)>, ResolverError> {
        let v = self
            .call(
                reqwest::Method::GET,
                &format!("/vaults/{vault_id}/items"),
                None,
            )
            .await?;
        let summaries: Vec<ItemSummary> =
            serde_json::from_value(v).map_err(|_| ResolverError::Malformed("item summaries"))?;
        let mut out = Vec::with_capacity(summaries.len());
        for s in &summaries {
            if s.vault_id != vault_id {
                return Err(ResolverError::ResponseMismatch);
            }
            let title_ct = b64_decode(&s.title_ciphertext, "title_ciphertext")?;
            let title = decrypt_title(vault_key, s.item_id.as_bytes(), &title_ct)?;
            out.push((s.item_id, title));
        }
        Ok(out)
    }

    /// Fetch and fully decrypt a single item.
    pub async fn get_item(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<DecryptedItem, ResolverError> {
        let v = self
            .call(
                reqwest::Method::GET,
                &format!("/vaults/{vault_id}/items/{item_id}"),
                None,
            )
            .await?;
        let rec: ItemRecord =
            serde_json::from_value(v).map_err(|_| ResolverError::Malformed("item record"))?;
        decrypt_item_record(vault_key, vault_id, item_id, &rec)
    }

    /// Copy an item into another vault, re-encrypting it under the target key.
    pub async fn copy_item(
        &self,
        source_vault_id: Uuid,
        item_id: Uuid,
        source_vault_key: &VaultKey,
        target_vault_id: Uuid,
        target_vault_key: &VaultKey,
        target_key_version: i32,
    ) -> Result<Uuid, ResolverError> {
        let item = self
            .get_item(source_vault_id, item_id, source_vault_key)
            .await?;
        self.create_item(
            target_vault_id,
            target_vault_key,
            item.content,
            &item.title,
            &item.tags,
            item.sensitive,
            target_key_version,
        )
        .await
    }

    /// Copy an item into another vault, then trash the source item.
    pub async fn move_item(
        &self,
        source_vault_id: Uuid,
        item_id: Uuid,
        source_vault_key: &VaultKey,
        target_vault_id: Uuid,
        target_vault_key: &VaultKey,
        target_key_version: i32,
    ) -> Result<Uuid, ResolverError> {
        let new_item_id = self
            .copy_item(
                source_vault_id,
                item_id,
                source_vault_key,
                target_vault_id,
                target_vault_key,
                target_key_version,
            )
            .await?;
        self.delete_item(source_vault_id, item_id).await?;
        Ok(new_item_id)
    }

    /// Update an existing item, re-encrypting body/title/tags under the item's
    /// existing content key.
    ///
    /// The existing `content_key_wrap` is fetched from the server and passed
    /// through unchanged so that key rotation (which re-wraps keys) remains
    /// independent of body edits (which re-encrypt body ciphertext under the
    /// same key).
    #[allow(clippy::too_many_arguments)]
    pub async fn update_item(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        vault_key: &VaultKey,
        content: ItemContent,
        title: &str,
        tags: &[String],
        sensitive: bool,
        version: i32,
    ) -> Result<(), ResolverError> {
        // GET the item to obtain its existing content_key_wrap, then unwrap the content key.
        let v = self
            .call(
                reqwest::Method::GET,
                &format!("/vaults/{vault_id}/items/{item_id}"),
                None,
            )
            .await?;
        let rec: ItemRecord =
            serde_json::from_value(v).map_err(|_| ResolverError::Malformed("item"))?;
        ensure_record_matches(vault_id, item_id, &rec)?;
        let wrap_bytes = b64_decode(&rec.content_key_wrap, "content_key_wrap")?;
        let content_key = unwrap_item_content_key(vault_key, item_id.as_bytes(), &wrap_bytes)?;
        // Updates preserve metadata flags that this API does not edit.
        let metadata_ct_bytes = b64_decode(&rec.metadata_ciphertext, "metadata_ciphertext")?;
        let existing_metadata =
            decrypt_metadata_json(vault_key, item_id.as_bytes(), &metadata_ct_bytes)?;
        let (favorite, reprompt) = metadata_flags(&existing_metadata);
        let req = build_update_request(
            vault_key,
            item_id,
            &content_key,
            &rec.content_key_wrap,
            &content,
            title,
            tags,
            sensitive,
            favorite,
            reprompt,
            version,
        )?;
        // Do not hold plaintext content across the network await.
        drop(content);
        self.call(
            reqwest::Method::PATCH,
            &format!("/vaults/{vault_id}/items/{item_id}"),
            Some(
                serde_json::to_value(req)
                    .map_err(|_| ResolverError::Malformed("serialize request"))?,
            ),
        )
        .await?;
        Ok(())
    }

    /// Soft-delete (trash) an item.
    pub async fn delete_item(&self, vault_id: Uuid, item_id: Uuid) -> Result<(), ResolverError> {
        self.call(
            reqwest::Method::DELETE,
            &format!("/vaults/{vault_id}/items/{item_id}"),
            None,
        )
        .await?;
        Ok(())
    }

    /// Restore a previously deleted (trashed) item.
    pub async fn restore_item(&self, vault_id: Uuid, item_id: Uuid) -> Result<(), ResolverError> {
        self.call(
            reqwest::Method::POST,
            &format!("/vaults/{vault_id}/items/{item_id}/restore"),
            None,
        )
        .await?;
        Ok(())
    }

    /// Fetch the current status of an approval request.
    pub async fn get_approval_status(
        &self,
        approval_id: Uuid,
    ) -> Result<ApprovalStatus, ResolverError> {
        let v = self
            .call(
                reqwest::Method::GET,
                &format!("/approvals/{approval_id}"),
                None,
            )
            .await?;
        let record: ApprovalStatusRecord =
            serde_json::from_value(v).map_err(|_| ResolverError::Malformed("approval record"))?;
        Ok(record.status)
    }
}

/// Approval request status returned by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Status-only projection of the service approval record.
#[derive(Deserialize)]
struct ApprovalStatusRecord {
    status: ApprovalStatus,
}

// ---------------------------------------------------------------------------
// Metered envelope unwrap
// ---------------------------------------------------------------------------

/// Unwrap the gateway's metered envelope, then the service DataResponse.
///
/// Expected shape: `{ "data": { ..., "body": { "data": <T> } } }` -> `<T>`.
///
/// Tolerates a direct `{ "data": <T> }` shape (plain DataResponse without the
/// metered wrapper) for callers that test against the service directly.
fn unwrap_metered(value: serde_json::Value) -> Result<serde_json::Value, ResolverError> {
    let outer = value
        .get("data")
        .ok_or(ResolverError::Malformed("missing data"))?;

    // A metered status is enforced on every path: an error envelope must not
    // be mistaken for a body just because it omits the "body" key.
    if let Some(status) = outer.get("status").and_then(serde_json::Value::as_u64)
        && !(200..300).contains(&status)
    {
        let body = outer.get("body").unwrap_or(outer);
        // Preserve ApprovalRequired instead of flattening it into 403.
        if status == 403
            && let Some(request_id) = crate::error::approval_request_id_from_value(body)
        {
            return Err(ResolverError::ApprovalRequired { request_id });
        }
        return Err(ResolverError::ServerError {
            status: status as u16,
            body: truncate_error_body(body.to_string()),
        });
    }

    // The metered envelope carries a "body"; a direct DataResponse does not.
    let service_resp = outer.get("body").unwrap_or(outer);
    // Unwrap the service DataResponse layer if present.
    let inner = service_resp.get("data").unwrap_or(service_resp);
    Ok(inner.clone())
}

// ---------------------------------------------------------------------------
// Bootstrap: fetch account secrets before any key source is available
// ---------------------------------------------------------------------------

/// Issue an authenticated GET through the gateway and return the unwrapped
/// inner payload. Factored out so it can be called before a
/// `VaultClient` is constructed (the bootstrap has no key source yet).
async fn gateway_get(
    http: &reqwest::Client,
    base_url: &str,
    bearer: &str,
    path: &str,
) -> Result<serde_json::Value, ResolverError> {
    validate_base_url(base_url)?;
    let url = format!("{base_url}{path}");
    let resp = http
        .get(&url)
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(ResolverError::transport)?;

    let status = resp.status();
    if !status.is_success() {
        let text = truncate_error_body(read_capped_text(resp, MAX_ERROR_BODY).await);
        return Err(ResolverError::ServerError {
            status: status.as_u16(),
            body: text,
        });
    }

    let body = read_capped(resp, MAX_GATEWAY_BODY).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| ResolverError::Malformed("response body"))?;

    unwrap_metered(value)
}

/// Issue an authenticated POST through the gateway with a JSON body and return
/// the unwrapped inner payload. Mirrors `gateway_get`.
async fn gateway_post(
    http: &reqwest::Client,
    base_url: &str,
    bearer: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value, ResolverError> {
    validate_base_url(base_url)?;
    let url = format!("{base_url}{path}");
    let resp = http
        .post(&url)
        .bearer_auth(bearer)
        .json(&body)
        .send()
        .await
        .map_err(ResolverError::transport)?;

    let status = resp.status();
    if !status.is_success() {
        let text = truncate_error_body(read_capped_text(resp, MAX_ERROR_BODY).await);
        return Err(ResolverError::ServerError {
            status: status.as_u16(),
            body: text,
        });
    }

    let body = read_capped(resp, MAX_GATEWAY_BODY).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| ResolverError::Malformed("response body"))?;

    unwrap_metered(value)
}

/// Issue an authenticated DELETE through the gateway and return the unwrapped
/// inner payload. Mirrors `gateway_get`.
async fn gateway_delete(
    http: &reqwest::Client,
    base_url: &str,
    bearer: &str,
    path: &str,
) -> Result<serde_json::Value, ResolverError> {
    validate_base_url(base_url)?;
    let url = format!("{base_url}{path}");
    let resp = http
        .delete(&url)
        .bearer_auth(bearer)
        .send()
        .await
        .map_err(ResolverError::transport)?;

    let status = resp.status();
    if !status.is_success() {
        let text = truncate_error_body(read_capped_text(resp, MAX_ERROR_BODY).await);
        return Err(ResolverError::ServerError {
            status: status.as_u16(),
            body: text,
        });
    }

    let body = read_capped(resp, MAX_GATEWAY_BODY).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| ResolverError::Malformed("response body"))?;

    unwrap_metered(value)
}

/// Build the canonical bytes that the server verifies the owner's signature
/// over when creating an agent identity.
///
/// Must match the server's `canonical_create_agent_bytes` implementation
/// byte-for-byte:
///   serde_json::to_vec(json!({
///       "display_name": display_name,
///       "issued_at": issued_at,
///       "kem_public_key": B64.encode(kem_pub_bytes),
///       "key_provenance": key_provenance,
///       "kms_key_id": kms_key_id,
///       "nonce": nonce,
///       "signing_public_key": B64.encode(signing_pub_bytes),
///   }))
///
/// `serde_json` without `preserve_order` uses a BTreeMap, so keys are sorted
/// alphabetically by key on both the signing and verifying sides.
pub fn canonical_create_agent_bytes(
    display_name: &str,
    kem_pub: &IdentityKemPublicKey,
    signing_pub: &IdentitySigningPublicKey,
    key_provenance: &serde_json::Value,
    kms_key_id: Option<&str>,
    issued_at: i64,
    nonce: &str,
) -> Vec<u8> {
    let canonical = serde_json::json!({
        "display_name": display_name,
        "kem_public_key": B64.encode(kem_pub.as_bytes()),
        "signing_public_key": B64.encode(signing_pub.as_bytes()),
        "key_provenance": key_provenance,
        "kms_key_id": kms_key_id,
        "issued_at": issued_at,
        "nonce": nonce,
    });
    serde_json::to_vec(&canonical).expect("canonical JSON serialization is infallible")
}

/// Create an agent identity owned by the calling user.
///
/// Signs the canonical request bytes with the owner's Ed25519 signing private
/// key and POSTs to `POST /identities/agents`. Returns the new `identity_id`.
pub async fn create_agent_identity(
    base_url: &str,
    bearer: &str,
    owner_signing_private: &IdentitySigningPrivateKey,
    display_name: &str,
    agent_kem_public: &IdentityKemPublicKey,
    agent_signing_public: &IdentitySigningPublicKey,
    key_provenance: serde_json::Value,
) -> Result<Uuid, ResolverError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(ResolverError::transport)?;

    let bu = base_url.trim_end_matches('/');

    // Bind the signature to a fresh, single-use moment so a captured
    // signature cannot be replayed to mint another agent later.
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let nonce = Uuid::new_v4().to_string();

    let canonical = canonical_create_agent_bytes(
        display_name,
        agent_kem_public,
        agent_signing_public,
        &key_provenance,
        None,
        issued_at,
        &nonce,
    );
    let sig = seren_secrets_crypto::signing::sign(owner_signing_private, &canonical);

    let body = serde_json::json!({
        "display_name": display_name,
        "kem_public_key": B64.encode(agent_kem_public.as_bytes()),
        "signing_public_key": B64.encode(agent_signing_public.as_bytes()),
        "key_provenance": key_provenance,
        "kms_key_id": serde_json::Value::Null,
        "issued_at": issued_at,
        "nonce": nonce,
        "signature": B64.encode(&sig),
    });

    let v = gateway_post(&http, bu, bearer, "/identities/agents", body).await?;

    let identity_id = v
        .get("identity_id")
        .and_then(|id| id.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(ResolverError::Malformed(
            "identity_id in create-agent response",
        ))?;

    Ok(identity_id)
}

/// Grant an agent identity membership in a vault.
///
/// Wraps the vault key for the agent's KEM public key, signs the grant
/// tuple with the granter's identity signing key, and POSTs to
/// `POST /vaults/{vault_id}/memberships`. The signature binds
/// (vault, grantee, access level, wrapped key) so the stored grant is
/// attributable and tamper-evident.
///
/// `access_level` is the snake_case string: "read", "write", or "admin".
#[allow(clippy::too_many_arguments)]
pub async fn grant_membership(
    base_url: &str,
    bearer: &str,
    granter_signing_private: &IdentitySigningPrivateKey,
    vault_id: Uuid,
    agent_identity_id: Uuid,
    vault_key: &VaultKey,
    agent_kem_public: &IdentityKemPublicKey,
    access_level: &str,
) -> Result<(), ResolverError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(ResolverError::transport)?;

    let bu = base_url.trim_end_matches('/');

    let wrapped = wrap_vault_key_for_identity(vault_key, agent_kem_public);

    let access_byte =
        seren_secrets_crypto::protocol::membership_grant::access_level_byte(access_level).ok_or(
            ResolverError::InvalidInput("access_level must be read, write, or admin"),
        )?;
    let signature = seren_secrets_crypto::protocol::membership_grant::sign_membership_grant(
        granter_signing_private,
        vault_id.as_bytes(),
        agent_identity_id.as_bytes(),
        access_byte,
        &wrapped,
    );
    let body = serde_json::json!({
        "identity_id": agent_identity_id,
        "wrapped_vault_key": B64.encode(&wrapped),
        "access_level": access_level,
        "granted_signature": B64.encode(&signature),
    });

    gateway_post(
        &http,
        bu,
        bearer,
        &format!("/vaults/{vault_id}/memberships"),
        body,
    )
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Agent listing and revocation
// ---------------------------------------------------------------------------

/// A vault that an agent identity has been granted access to.
#[derive(Debug, Clone, Serialize)]
pub struct AgentVaultGrantInfo {
    pub vault_id: Uuid,
    /// Access level string: "read", "write", or "admin".
    pub access_level: String,
    pub granted_at: Timestamp,
}

/// Flattened view of a provisioned agent identity and the vaults it can access.
///
/// The listing endpoint returns only active agents, so there is no `revoked_at`.
#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub identity_id: Uuid,
    pub display_name: String,
    pub created_at: Timestamp,
    pub granted_vaults: Vec<AgentVaultGrantInfo>,
}

/// Wire shape of one entry from `GET /identities/agents`
/// (`DataResponse<Vec<AgentSummary>>`, inner payload after envelope unwrap).
#[derive(Deserialize)]
struct AgentSummaryWire {
    identity: AgentIdentityWire,
    granted_vaults: Vec<AgentVaultGrantWire>,
}

/// Nested `identity` object of an `AgentSummaryWire`. Only the fields the
/// client pulls up into `AgentInfo` are declared; serde drops the rest.
#[derive(Deserialize)]
struct AgentIdentityWire {
    identity_id: Uuid,
    display_name: String,
    #[serde(default)]
    created_at: String,
}

/// Nested `granted_vaults` entry of an `AgentSummaryWire`.
#[derive(Deserialize)]
struct AgentVaultGrantWire {
    vault_id: Uuid,
    access_level: String,
    #[serde(default)]
    granted_at: String,
}

impl TryFrom<AgentSummaryWire> for AgentInfo {
    type Error = ResolverError;

    fn try_from(wire: AgentSummaryWire) -> Result<Self, Self::Error> {
        let created_at = wire
            .identity
            .created_at
            .parse::<Timestamp>()
            .map_err(|_| ResolverError::Malformed("agent created_at"))?;
        let granted_vaults = wire
            .granted_vaults
            .into_iter()
            .map(|g| {
                Ok(AgentVaultGrantInfo {
                    vault_id: g.vault_id,
                    access_level: g.access_level,
                    granted_at: g
                        .granted_at
                        .parse::<Timestamp>()
                        .map_err(|_| ResolverError::Malformed("grant granted_at"))?,
                })
            })
            .collect::<Result<Vec<_>, ResolverError>>()?;
        Ok(AgentInfo {
            identity_id: wire.identity.identity_id,
            display_name: wire.identity.display_name,
            created_at,
            granted_vaults,
        })
    }
}

/// List the agent identities owned by the calling user.
///
/// Calls `GET /identities/agents` through the gateway and flattens the nested
/// `DataResponse<Vec<AgentSummary>>` wire shape into `AgentInfo` records.
pub async fn list_agents(base_url: &str, bearer: &str) -> Result<Vec<AgentInfo>, ResolverError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(ResolverError::transport)?;

    let bu = base_url.trim_end_matches('/');

    let v = gateway_get(&http, bu, bearer, "/identities/agents").await?;
    let wire: Vec<AgentSummaryWire> =
        serde_json::from_value(v).map_err(|_| ResolverError::Malformed("agent list"))?;
    wire.into_iter().map(AgentInfo::try_from).collect()
}

/// Revoke an identity's membership in a vault.
///
/// Calls `DELETE /vaults/{vault_id}/memberships/{identity_id}` through the
/// gateway.
pub async fn revoke_membership(
    base_url: &str,
    bearer: &str,
    vault_id: Uuid,
    identity_id: Uuid,
) -> Result<(), ResolverError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(ResolverError::transport)?;

    let bu = base_url.trim_end_matches('/');

    gateway_delete(
        &http,
        bu,
        bearer,
        &format!("/vaults/{vault_id}/memberships/{identity_id}"),
    )
    .await?;

    Ok(())
}

/// Revoke an agent identity.
///
/// Calls `POST /identities/{identity_id}/revoke` through the gateway. The
/// route is path-only; the handler has no body extractor, so the empty JSON
/// object body is ignored server-side.
pub async fn revoke_agent_identity(
    base_url: &str,
    bearer: &str,
    identity_id: Uuid,
) -> Result<(), ResolverError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(ResolverError::transport)?;

    let bu = base_url.trim_end_matches('/');

    gateway_post(
        &http,
        bu,
        bearer,
        &format!("/identities/{identity_id}/revoke"),
        serde_json::json!({}),
    )
    .await?;

    Ok(())
}

/// Fetch the caller's account secrets and identity through the gateway and
/// build a master-password key source.
///
/// Used before any vault key is available: we cannot construct a
/// `VaultClient` yet because we don't have an
/// `IdentityKemPrivateKey`, so the bootstrap fetches the two gateway endpoints
/// with a bare reqwest client, assembles `AccountSecrets`, and returns the
/// `VaultKeySource` the caller can pass to `VaultClientConfig`.
pub async fn fetch_master_password_key_source(
    base_url: &str,
    bearer: &str,
    master_password: Zeroizing<Vec<u8>>,
) -> Result<VaultKeySource, ResolverError> {
    let http = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(ResolverError::transport)?;

    let bu = base_url.trim_end_matches('/');

    let secrets_v = gateway_get(&http, bu, bearer, "/account/secrets").await?;
    let identity_v = gateway_get(&http, bu, bearer, "/identities/me").await?;

    let secrets: AccountSecretsRecord = serde_json::from_value(secrets_v)
        .map_err(|_| ResolverError::Malformed("account secrets"))?;
    let identity: IdentityRecord =
        serde_json::from_value(identity_v).map_err(|_| ResolverError::Malformed("identity"))?;

    let account_secrets = assemble_account_secrets(secrets, identity)?;

    Ok(VaultKeySource::MasterPassword {
        secrets: Box::new(account_secrets),
        master_password,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use seren_secrets_crypto::kdf::{KdfAlgorithm, KdfParams};
    use seren_secrets_crypto::keys::{IdentityKemKeypair, IdentitySigningKeypair};
    use seren_secrets_crypto::protocol::account::account_setup_with_params;
    use seren_secrets_crypto::protocol::item::SecureNoteContent;
    use seren_secrets_crypto::protocol::vault::{
        encrypt_vault_name, generate_vault_key, wrap_vault_key_for_identity,
    };

    #[test]
    fn unwrap_metered_enforces_error_status_without_body() {
        // A metered envelope reporting a non-2xx status must surface as an
        // error even when the error shape carries no "body" key, rather than
        // being mistaken for a successful payload.
        let value = serde_json::json!({ "data": { "status": 403 } });
        let err = unwrap_metered(value).unwrap_err();
        assert!(matches!(
            err,
            ResolverError::ServerError { status: 403, .. }
        ));
    }

    #[test]
    fn unwrap_metered_descends_metered_envelope() {
        let value = serde_json::json!({
            "data": { "status": 200, "body": { "data": { "field": "value" } } }
        });
        assert_eq!(
            unwrap_metered(value).unwrap(),
            serde_json::json!({ "field": "value" })
        );
    }

    #[test]
    fn unwrap_metered_tolerates_direct_data_response() {
        let value = serde_json::json!({ "data": { "field": "value" } });
        assert_eq!(
            unwrap_metered(value).unwrap(),
            serde_json::json!({ "field": "value" })
        );
    }

    #[test]
    fn unwrap_metered_surfaces_approval_required() {
        let request_id = "11111111-1111-1111-1111-111111111111";
        let value = serde_json::json!({
            "data": {
                "status": 403,
                "body": {
                    "error": {
                        "message": "approval required",
                        "code": 403,
                        "approval_request_id": request_id,
                    }
                }
            }
        });
        match unwrap_metered(value).unwrap_err() {
            ResolverError::ApprovalRequired { request_id: got } => {
                assert_eq!(got, request_id.parse::<Uuid>().unwrap());
            }
            other => panic!("expected ApprovalRequired, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_metered_non_approval_403_stays_server_error() {
        let value = serde_json::json!({
            "data": { "status": 403, "body": { "error": { "message": "forbidden", "code": 403 } } }
        });
        assert!(matches!(
            unwrap_metered(value).unwrap_err(),
            ResolverError::ServerError { status: 403, .. }
        ));
    }

    fn fast_kdf_params(salt_byte: u8) -> KdfParams {
        KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
            salt: vec![salt_byte; 16],
        }
    }

    #[test]
    fn assemble_account_secrets_round_trips() {
        let kdf = fast_kdf_params(1);
        let recovery_kdf = fast_kdf_params(2);

        let bundle =
            account_setup_with_params(b"hunter2", kdf.clone(), recovery_kdf.clone()).unwrap();
        let original = &bundle.secrets;

        // Build wire records by base64-encoding the raw bytes (as the gateway would return them).
        let secrets_record = AccountSecretsRecord {
            kdf_params: serde_json::to_value(&kdf).unwrap(),
            recovery_kdf_params: serde_json::to_value(&recovery_kdf).unwrap(),
            account_key_wrap: B64.encode(&original.account_key_wrap),
            account_kem_private_wrap: B64.encode(&original.account_kem_private_wrap),
            account_signing_private_wrap: B64.encode(&original.account_signing_private_wrap),
            recovery_key_wrap: B64.encode(&original.recovery_key_wrap),
        };
        let identity_record = IdentityRecord {
            kem_public_key: B64.encode(original.kem_public_key.as_bytes()),
            signing_public_key: B64.encode(original.signing_public_key.as_bytes()),
        };

        let assembled =
            assemble_account_secrets(secrets_record, identity_record).expect("assemble");

        // Compare field by field (AccountSecrets derives PartialEq).
        assert_eq!(assembled, *original);
    }

    #[test]
    fn unwrap_metered_then_data_response() {
        let env = serde_json::json!({
            "data": {
                "status": 200,
                "cost": "0",
                "body": {
                    "data": { "user_id": "x" }
                }
            }
        });
        assert_eq!(unwrap_metered(env).unwrap()["user_id"], "x");
    }

    #[test]
    fn unwrap_metered_preserves_inner_error_status() {
        let env = serde_json::json!({
            "data": {
                "status": 403,
                "body": {
                    "error": {
                        "code": 403,
                        "message": "approval required"
                    }
                }
            }
        });
        let err = unwrap_metered(env).unwrap_err();
        match err {
            ResolverError::ServerError { status, body } => {
                assert_eq!(status, 403);
                assert!(body.contains("approval required"));
            }
            other => panic!("expected ServerError, got {other:?}"),
        }
    }

    #[test]
    fn unwrap_tolerates_direct_shape() {
        let d = serde_json::json!({ "data": { "vault_id": "v" } });
        assert_eq!(unwrap_metered(d).unwrap()["vault_id"], "v");
    }

    #[test]
    fn approval_status_deserializes_service_variants() {
        for (raw, expected) in [
            ("pending", ApprovalStatus::Pending),
            ("approved", ApprovalStatus::Approved),
            ("denied", ApprovalStatus::Denied),
            ("expired", ApprovalStatus::Expired),
        ] {
            let got: ApprovalStatus = serde_json::from_value(serde_json::json!(raw)).unwrap();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn approval_status_parses_from_metered_record() {
        let value = serde_json::json!({
            "data": { "status": 200, "body": { "data": {
                "request_id": "44444444-4444-4444-4444-444444444444",
                "requesting_identity_id": "55555555-5555-5555-5555-555555555555",
                "target_kind": "item",
                "target_id": "66666666-6666-6666-6666-666666666666",
                "status": "approved",
                "expires_at": "2030-01-01T00:00:00Z",
                "created_at": "2030-01-01T00:00:00Z"
            } } }
        });
        let inner = unwrap_metered(value).unwrap();
        let record: ApprovalStatusRecord = serde_json::from_value(inner).unwrap();
        assert_eq!(record.status, ApprovalStatus::Approved);
    }

    // (a) build_create_request round-trip: encrypt then manually decrypt
    #[test]
    fn build_create_request_round_trips_secure_note() {
        let vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();
        let (body_doc, body_text) = seren_secrets_crypto::prose::from_plaintext("my private note");
        let content = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            ..Default::default()
        });
        let title = "Test Note";
        let tags: Vec<String> = vec![];

        let req = build_create_request(&vault_key, item_id, &content, title, &tags, true, 1)
            .expect("build request");

        // Verify item_id is preserved and blind index is empty.
        assert_eq!(req.item_id, item_id);
        assert_eq!(req.title_blind_index, "");
        assert!(req.sensitive);
        assert_eq!(req.wrapping_key_version, Some(1));
        assert!(req.tags_ciphertext.is_none());

        // Decrypt title back.
        let title_ct = B64.decode(req.title_ciphertext.as_bytes()).unwrap();
        let recovered_title = decrypt_title(&vault_key, item_id.as_bytes(), &title_ct).unwrap();
        assert_eq!(recovered_title, title);

        // Decrypt content via content key wrap -> body ciphertext.
        let ck_wrap = B64.decode(req.content_key_wrap.as_bytes()).unwrap();
        let content_ct = B64.decode(req.content_ciphertext.as_bytes()).unwrap();
        let ck = unwrap_item_content_key(&vault_key, item_id.as_bytes(), &ck_wrap).unwrap();
        let recovered_content =
            decrypt_item_with_content_key(&ck, item_id.as_bytes(), &content_ct).unwrap();
        assert_eq!(recovered_content, content);
    }

    // (b) decrypt_vault_record: seal a vault key, encrypt a name, round-trip
    #[test]
    fn decrypt_vault_record_unwraps_key_and_name() {
        let vault_key = generate_vault_key();
        let kp = IdentityKemKeypair::generate();
        let vault_id = Uuid::new_v4();

        let wrapped = wrap_vault_key_for_identity(&vault_key, &kp.public);
        let name_ct = encrypt_vault_name(&vault_key, vault_id.as_bytes(), "Personal Vault");

        let rec = VaultRecord {
            vault_id,
            name_ciphertext: B64.encode(&name_ct),
            description_ciphertext: None,
            vault_key_version: Some(3),
            wrapped_vault_key: Some(B64.encode(&wrapped)),
            requires_approval: serde_json::Value::Null,
            created_at: String::new(),
            updated_at: String::new(),
        };

        let dv = decrypt_vault_record(&kp.private, &rec).expect("decrypt vault record");
        assert_eq!(dv.vault_id, vault_id);
        assert_eq!(dv.name, "Personal Vault");
        assert_eq!(dv.key_version, 3);
        // Confirm the recovered key can decrypt the original name.
        let name_ct2 = encrypt_vault_name(&dv.key, vault_id.as_bytes(), "x");
        let vk_bytes = vault_key.as_bytes();
        let recovered_key_bytes = dv.key.as_bytes();
        assert_eq!(vk_bytes, recovered_key_bytes);
        let _ = name_ct2; // suppress unused warning
    }

    // (c) round-trip an ItemRecord through decrypt_item_record
    #[test]
    fn decrypt_item_record_round_trips() {
        let vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();
        let title = "GitHub SSH Key";
        let tags = vec!["work".to_string(), "infra".to_string()];
        let (body_doc, body_text) =
            seren_secrets_crypto::prose::from_plaintext("note about this key");
        let content = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            ..Default::default()
        });
        let metadata_json =
            r#"{"item_kind":"secure_note","favorite":false,"sensitive":false,"reprompt":false}"#;

        let content_key = generate_item_content_key();
        let ck_wrap = wrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key);
        let content_ct =
            encrypt_item_with_content_key(&content_key, item_id.as_bytes(), &content).unwrap();
        let title_ct = encrypt_title(&vault_key, item_id.as_bytes(), title);
        let tags_ct = encrypt_tags(&vault_key, item_id.as_bytes(), &tags).unwrap();
        let metadata_ct = encrypt_metadata_json(&vault_key, item_id.as_bytes(), metadata_json);

        let rec = ItemRecord {
            item_id,
            vault_id,
            title_ciphertext: B64.encode(&title_ct),
            content_ciphertext: B64.encode(&content_ct),
            tags_ciphertext: Some(B64.encode(&tags_ct)),
            title_blind_index: String::new(),
            content_key_wrap: B64.encode(&ck_wrap),
            metadata_ciphertext: B64.encode(&metadata_ct),
            sensitive: false,
            vault_key_version: Some(1),
            created_at: String::new(),
            updated_at: String::new(),
            archived_at: None,
            trashed_at: None,
        };

        let di =
            decrypt_item_record(&vault_key, vault_id, item_id, &rec).expect("decrypt item record");
        assert_eq!(di.item_id, item_id);
        assert_eq!(di.title, title);
        assert_eq!(di.tags, tags);
        assert_eq!(di.content, content);
        assert_eq!(di.metadata_json, metadata_json);
    }

    // Returned records must match the requested vault/item ids.
    #[test]
    fn decrypt_item_record_rejects_mismatched_ids() {
        let vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();
        let vault_id = Uuid::new_v4();
        let (body_doc, body_text) = seren_secrets_crypto::prose::from_plaintext("secret note");
        let content = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            ..Default::default()
        });
        let metadata_json =
            r#"{"item_kind":"secure_note","favorite":false,"sensitive":false,"reprompt":false}"#;

        let content_key = generate_item_content_key();
        let ck_wrap = wrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key);
        let content_ct =
            encrypt_item_with_content_key(&content_key, item_id.as_bytes(), &content).unwrap();
        let title_ct = encrypt_title(&vault_key, item_id.as_bytes(), "title");
        let metadata_ct = encrypt_metadata_json(&vault_key, item_id.as_bytes(), metadata_json);

        let rec = ItemRecord {
            item_id,
            vault_id,
            title_ciphertext: B64.encode(&title_ct),
            content_ciphertext: B64.encode(&content_ct),
            tags_ciphertext: None,
            title_blind_index: String::new(),
            content_key_wrap: B64.encode(&ck_wrap),
            metadata_ciphertext: B64.encode(&metadata_ct),
            sensitive: true,
            vault_key_version: Some(1),
            created_at: String::new(),
            updated_at: String::new(),
            archived_at: None,
            trashed_at: None,
        };

        // Server returns this (valid) record when a DIFFERENT item was requested.
        assert!(matches!(
            decrypt_item_record(&vault_key, vault_id, Uuid::new_v4(), &rec),
            Err(ResolverError::ResponseMismatch)
        ));
        // Server returns it under a different vault than requested.
        assert!(matches!(
            decrypt_item_record(&vault_key, Uuid::new_v4(), item_id, &rec),
            Err(ResolverError::ResponseMismatch)
        ));
        // The honest case (ids match what was requested) still decrypts.
        decrypt_item_record(&vault_key, vault_id, item_id, &rec).expect("matching ids decrypt");
    }

    // (d) build_update_request: content_key_wrap is unchanged; new body decrypts correctly
    #[test]
    fn build_update_request_reuses_content_key_wrap() {
        let vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();

        // Generate a content key and wrap it (simulating what is stored on the server).
        let content_key = generate_item_content_key();
        let ck_wrap_bytes = wrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key);
        let content_key_wrap_b64 = B64.encode(&ck_wrap_bytes);

        // Build an update request with new content.
        let (body_doc, body_text) = seren_secrets_crypto::prose::from_plaintext("updated note");
        let new_content = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            ..Default::default()
        });
        let title = "Updated Title";
        let tags: Vec<String> = vec!["tag1".to_string()];

        let req = build_update_request(
            &vault_key,
            item_id,
            &content_key,
            &content_key_wrap_b64,
            &new_content,
            title,
            &tags,
            false,
            false,
            false,
            2,
        )
        .expect("build update request");

        // The content_key_wrap must be passed through UNCHANGED.
        assert_eq!(
            req.content_key_wrap, content_key_wrap_b64,
            "content_key_wrap must be identical to the input (not re-wrapped)"
        );

        assert_eq!(req.title_blind_index, "");
        assert!(!req.sensitive);
        assert_eq!(req.wrapping_key_version, Some(2));

        // Decrypting the content ciphertext with the SAME content key must yield the new content.
        let content_ct = B64.decode(req.content_ciphertext.as_bytes()).unwrap();
        let recovered =
            decrypt_item_with_content_key(&content_key, item_id.as_bytes(), &content_ct)
                .expect("decrypt content");
        assert_eq!(recovered, new_content);

        // Decrypting the title ciphertext must yield the new title.
        let title_ct = B64.decode(req.title_ciphertext.as_bytes()).unwrap();
        let recovered_title = decrypt_title(&vault_key, item_id.as_bytes(), &title_ct).unwrap();
        assert_eq!(recovered_title, title);

        // Tags ciphertext must be present and decrypt correctly.
        let tags_b64 = req.tags_ciphertext.expect("tags_ciphertext should be Some");
        let tags_ct = B64.decode(tags_b64.as_bytes()).unwrap();
        let recovered_tags = decrypt_tags(&vault_key, item_id.as_bytes(), &tags_ct).unwrap();
        assert_eq!(recovered_tags, tags);
    }

    #[test]
    fn metadata_flags_parses_favorite_and_reprompt() {
        assert_eq!(
            metadata_flags(
                r#"{"item_kind":"login","favorite":true,"sensitive":false,"reprompt":true}"#
            ),
            (true, true)
        );
        assert_eq!(
            metadata_flags(
                r#"{"item_kind":"login","favorite":false,"sensitive":true,"reprompt":false}"#
            ),
            (false, false)
        );
        // Absent fields and malformed JSON both default to (false, false).
        assert_eq!(metadata_flags(r#"{"item_kind":"login"}"#), (false, false));
        assert_eq!(metadata_flags("not json"), (false, false));
    }

    #[test]
    fn build_update_request_preserves_favorite_and_reprompt() {
        // An update must not silently clear flags the caller never edits.
        let vault_key = generate_vault_key();
        let item_id = Uuid::new_v4();
        let content_key = generate_item_content_key();
        let ck_wrap_bytes = wrap_item_content_key(&vault_key, item_id.as_bytes(), &content_key);
        let content_key_wrap_b64 = B64.encode(&ck_wrap_bytes);

        let (body_doc, body_text) = seren_secrets_crypto::prose::from_plaintext("note");
        let content = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            ..Default::default()
        });

        let req = build_update_request(
            &vault_key,
            item_id,
            &content_key,
            &content_key_wrap_b64,
            &content,
            "title",
            &[],
            true, // sensitive
            true, // favorite
            true, // reprompt
            1,
        )
        .expect("build update request");

        let metadata_ct = B64.decode(req.metadata_ciphertext.as_bytes()).unwrap();
        let metadata_json =
            decrypt_metadata_json(&vault_key, item_id.as_bytes(), &metadata_ct).unwrap();
        assert_eq!(metadata_flags(&metadata_json), (true, true));
        let value: serde_json::Value = serde_json::from_str(&metadata_json).unwrap();
        assert_eq!(value.get("sensitive").and_then(|v| v.as_bool()), Some(true));
    }

    // Missing wrapped_vault_key returns Malformed error.
    #[test]
    fn decrypt_vault_record_missing_key_returns_malformed() {
        let vault_id = Uuid::new_v4();
        let vault_key = generate_vault_key();
        let name_ct = encrypt_vault_name(&vault_key, vault_id.as_bytes(), "x");
        let rec = VaultRecord {
            vault_id,
            name_ciphertext: B64.encode(&name_ct),
            description_ciphertext: None,
            vault_key_version: None,
            wrapped_vault_key: None,
            requires_approval: serde_json::Value::Null,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let kp = IdentityKemKeypair::generate();
        let err = decrypt_vault_record(&kp.private, &rec).unwrap_err();
        assert!(matches!(err, ResolverError::Malformed(_)));
    }

    // The canonical layout must match the bytes that are signed.
    #[test]
    fn canonical_create_agent_bytes_sign_verify_round_trip() {
        let owner_kp = IdentitySigningKeypair::generate();
        let agent_kem_kp = IdentityKemKeypair::generate();
        let agent_sign_kp = IdentitySigningKeypair::generate();

        let provenance = serde_json::json!({ "kind": "software", "version": 1 });

        let canonical = canonical_create_agent_bytes(
            "my-agent",
            &agent_kem_kp.public,
            &agent_sign_kp.public,
            &provenance,
            None,
            1_700_000_000,
            "test-nonce",
        );

        let sig = seren_secrets_crypto::signing::sign(&owner_kp.private, &canonical);
        seren_secrets_crypto::signing::verify(&owner_kp.public, &canonical, &sig)
            .expect("signature must verify over canonical bytes");

        // A different message must not verify.
        let err =
            seren_secrets_crypto::signing::verify(&owner_kp.public, b"tampered", &sig).unwrap_err();
        assert!(matches!(
            err,
            seren_secrets_crypto::error::CryptoError::InvalidSignature
        ));
    }

    // wrap_vault_key_for_identity / unwrap_vault_key round-trip for grant_membership.
    #[test]
    fn wrap_vault_key_for_identity_round_trips() {
        let vault_key = generate_vault_key();
        let agent_kem_kp = IdentityKemKeypair::generate();

        let wrapped = wrap_vault_key_for_identity(&vault_key, &agent_kem_kp.public);
        let recovered = seren_secrets_crypto::protocol::vault::unwrap_vault_key(
            &agent_kem_kp.private,
            &wrapped,
        )
        .expect("unwrap must succeed");

        assert_eq!(vault_key.as_bytes(), recovered.as_bytes());
    }

    // list_agents wire-shape deserialize + AgentInfo::from flattening. Exercises
    // the mapping without any network: feed a representative array (one agent,
    // two vault grants) and assert the flattened fields.
    #[test]
    fn agent_summary_wire_flattens_into_agent_info() {
        let identity_id = Uuid::new_v4();
        let vault_a = Uuid::new_v4();
        let vault_b = Uuid::new_v4();

        let payload = serde_json::json!([
            {
                "identity": {
                    "identity_id": identity_id,
                    "kind": "agent",
                    "owner_user_id": Uuid::new_v4(),
                    "display_name": "ci-bot",
                    "kem_public_key": "AAAA",
                    "signing_public_key": "BBBB",
                    "key_provenance": {},
                    "kms_key_id": null,
                    "created_at": "2026-05-30T00:00:00Z",
                    "updated_at": "2026-05-30T00:00:00Z",
                    "last_seen_at": null,
                    "revoked_at": null
                },
                "granted_vaults": [
                    { "vault_id": vault_a, "access_level": "read", "granted_at": "2026-05-30T01:00:00Z" },
                    { "vault_id": vault_b, "access_level": "admin", "granted_at": "2026-05-30T02:00:00Z" }
                ]
            }
        ]);

        let wire: Vec<AgentSummaryWire> =
            serde_json::from_value(payload).expect("deserialize agent list");
        let agents: Vec<AgentInfo> = wire
            .into_iter()
            .map(AgentInfo::try_from)
            .collect::<Result<_, _>>()
            .expect("map agent list");

        assert_eq!(agents.len(), 1);
        let agent = &agents[0];
        assert_eq!(agent.identity_id, identity_id);
        assert_eq!(agent.display_name, "ci-bot");
        assert_eq!(
            agent.created_at,
            "2026-05-30T00:00:00Z".parse::<Timestamp>().unwrap()
        );

        assert_eq!(agent.granted_vaults.len(), 2);
        assert_eq!(agent.granted_vaults[0].vault_id, vault_a);
        assert_eq!(agent.granted_vaults[0].access_level, "read");
        assert_eq!(
            agent.granted_vaults[0].granted_at,
            "2026-05-30T01:00:00Z".parse::<Timestamp>().unwrap()
        );
        assert_eq!(agent.granted_vaults[1].vault_id, vault_b);
        assert_eq!(agent.granted_vaults[1].access_level, "admin");
    }
}

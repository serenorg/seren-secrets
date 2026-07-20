//! `seren-secrets://vault-id/item-id/field-name` resolver against the
//! upstream secrets service.
//!
//! Trust model: end-to-end. The server returns ciphertext plus the caller's
//! wrapped vault key. This module unwraps the vault key with the caller's
//! KEM private key, decrypts the item content, and extracts the requested
//! field, all in process. The server never sees a content key or plaintext.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use jiff::Timestamp;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use seren_secrets_crypto::keys::{
    IdentityKemKeypair, IdentityKemPrivateKey, IdentitySigningKeypair, VaultKey,
};
use seren_secrets_crypto::protocol::item::{
    ApiCredentialContent, DecryptedItemContent, ItemContent, LoginContent, SecureNoteContent,
};
use seren_secrets_crypto::protocol::resolve::{
    ResolveRequest as SignedResolve, build_resolve_signature,
};
use seren_secrets_crypto::protocol::vault::unwrap_vault_key;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ResolverError;
use crate::http::{
    MAX_ERROR_BODY, MAX_RESOLVE_BODY, read_capped, read_capped_text, validate_base_url,
};
use crate::types::{AgentSecretResolver, ResolutionContext, ResolvedSecret, SecretSource};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SerenSecretsResolver {
    http: reqwest::Client,
    base_url: String,
    /// API bearer token. Wrapped in `Zeroizing` so the secret bytes are
    /// scrubbed from memory when the resolver drops, even on panic paths.
    bearer_token: Zeroizing<String>,
    /// The caller's identity_id (agent or user). Bound into the resolve
    /// signature so a captured signature can't be replayed under a different
    /// identity.
    caller_identity_id: Uuid,
    /// Signing keys for the resolve request signature.
    signing_keypair: IdentitySigningKeypair,
    /// KEM keypair for unwrapping the vault key. The public half tells the
    /// crypto crate which key to verify the sealed box against; the private
    /// half is held in process (in the agent host's keystore for local
    /// agents; in a KMS-protected slot for cloud agents).
    kem_keypair: IdentityKemKeypair,
}

pub struct SerenSecretsResolverConfig {
    pub base_url: String,
    pub bearer_token: String,
    pub caller_identity_id: Uuid,
    pub signing_keypair: IdentitySigningKeypair,
    pub kem_keypair: IdentityKemKeypair,
}

impl SerenSecretsResolver {
    pub fn new(config: SerenSecretsResolverConfig) -> Result<Self, ResolverError> {
        validate_base_url(&config.base_url)?;
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(ResolverError::transport)?;
        Ok(Self {
            http,
            base_url: config.base_url.trim_end_matches('/').to_string(),
            bearer_token: Zeroizing::new(config.bearer_token),
            caller_identity_id: config.caller_identity_id,
            signing_keypair: config.signing_keypair,
            kem_keypair: config.kem_keypair,
        })
    }
}

#[derive(Debug, Serialize)]
struct ResolveBody<'a> {
    uri: &'a str,
    issued_at: Timestamp,
    nonce: Uuid,
    request_signature: String,
}

#[derive(Debug, Deserialize)]
struct ResolveEnvelope {
    data: ResolveResponseBody,
}

#[derive(Debug, Deserialize)]
struct ResolveResponseBody {
    vault_id: Uuid,
    item_id: Uuid,
    field_name: String,
    content_ciphertext: String,
    content_key_wrap: String,
    wrapped_vault_key: String,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    approval_request_id: Option<Uuid>,
}

#[async_trait]
impl AgentSecretResolver for SerenSecretsResolver {
    async fn resolve(
        &self,
        uri: &str,
        ctx: &ResolutionContext,
    ) -> Result<ResolvedSecret, ResolverError> {
        let (vault_id, item_id, requested_field) = parse_seren_secrets_uri(uri)?;

        let issued_at = Timestamp::now();
        let nonce = Uuid::new_v4();
        let signed = SignedResolve {
            uri: uri.to_string(),
            caller_identity_id: self.caller_identity_id,
            issued_at,
            nonce,
        };
        let signature = build_resolve_signature(&self.signing_keypair.private, &signed)?;
        let body = ResolveBody {
            uri,
            issued_at,
            nonce,
            request_signature: B64.encode(&signature),
        };

        let url = format!("{}/resolve", self.base_url);
        let mut request = self
            .http
            .post(&url)
            .bearer_auth(&*self.bearer_token)
            .header("X-Seren-Organization-Id", ctx.organization_id.to_string())
            .header("X-Seren-User-Id", ctx.user_id.to_string())
            .headers(correlation_headers(ctx));
        if let Some(agent_identity_id) = ctx.agent_identity_id {
            request = request.header("X-Seren-Agent-Identity-Id", agent_identity_id.to_string());
        }
        let response = request
            .json(&body)
            .send()
            .await
            .map_err(ResolverError::transport)?;

        let status = response.status();
        if status == StatusCode::FORBIDDEN {
            // The server returns 403 ApprovalRequired with the approval_request_id
            // embedded in the structured error body. Surface it so the caller can
            // wait for the user's approval and retry.
            let body = read_capped(response, MAX_ERROR_BODY)
                .await
                .unwrap_or_default();
            if let Ok(env) = serde_json::from_slice::<ErrorEnvelope>(&body)
                && let Some(request_id) = env.error.approval_request_id
            {
                return Err(ResolverError::ApprovalRequired { request_id });
            }
            return Err(ResolverError::ServerError {
                status: status.as_u16(),
                body: "forbidden".into(),
            });
        }
        if !status.is_success() {
            let text =
                crate::error::truncate_error_body(read_capped_text(response, MAX_ERROR_BODY).await);
            return Err(ResolverError::ServerError {
                status: status.as_u16(),
                body: text,
            });
        }

        let body = read_capped(response, MAX_RESOLVE_BODY).await?;
        let envelope: ResolveEnvelope =
            serde_json::from_slice(&body).map_err(|_| ResolverError::Malformed("response body"))?;
        let payload = envelope.data;

        let content = decrypt_resolve_payload(
            &payload,
            vault_id,
            item_id,
            &requested_field,
            &self.kem_keypair.private,
        )?;

        let plaintext = extract_field(content.as_ref(), &requested_field)?;
        drop(content);

        Ok(ResolvedSecret {
            plaintext: Zeroizing::new(plaintext),
            field_name: requested_field,
            source: SecretSource::SerenSecrets,
        })
    }
}

fn decrypt_resolve_payload(
    payload: &ResolveResponseBody,
    expected_vault_id: Uuid,
    expected_item_id: Uuid,
    requested_field: &str,
    kem_private: &IdentityKemPrivateKey,
) -> Result<DecryptedItemContent, ResolverError> {
    // Sanity-check the response URI components against the URI we requested.
    if payload.vault_id != expected_vault_id || payload.item_id != expected_item_id {
        return Err(ResolverError::Malformed(
            "response vault_id/item_id mismatch",
        ));
    }
    if payload.field_name != requested_field {
        return Err(ResolverError::Malformed("response field_name mismatch"));
    }

    let wrapped_vault_key = B64
        .decode(payload.wrapped_vault_key.as_bytes())
        .map_err(|_| ResolverError::Malformed("wrapped_vault_key base64"))?;
    let content_key_wrap = B64
        .decode(payload.content_key_wrap.as_bytes())
        .map_err(|_| ResolverError::Malformed("content_key_wrap base64"))?;
    let content_ciphertext = B64
        .decode(payload.content_ciphertext.as_bytes())
        .map_err(|_| ResolverError::Malformed("content_ciphertext base64"))?;

    let vault_key: VaultKey = unwrap_vault_key(kem_private, &wrapped_vault_key)?;

    let content_key = seren_secrets_crypto::protocol::item::unwrap_item_content_key(
        &vault_key,
        expected_item_id.as_bytes(),
        &content_key_wrap,
    )?;
    seren_secrets_crypto::protocol::item::decrypt_item_with_content_key(
        &content_key,
        expected_item_id.as_bytes(),
        &content_ciphertext,
    )
    .map_err(ResolverError::from)
}

fn correlation_headers(ctx: &ResolutionContext) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(correlation_id) = ctx.correlation_id {
        let value = reqwest::header::HeaderValue::from_str(&correlation_id.to_string());
        if let Ok(value) = value {
            headers.insert("X-Seren-Correlation-Id", value);
        }
    }
    headers
}

fn parse_seren_secrets_uri(uri: &str) -> Result<(Uuid, Uuid, String), ResolverError> {
    // The signed URI string must name exactly one (vault, item, field) triple:
    // canonical hyphenated UUIDs, one field segment, and no query, fragment,
    // or whitespace.
    if uri.chars().any(char::is_whitespace) {
        return Err(ResolverError::InvalidUri("uri must not contain whitespace"));
    }
    let rest = uri
        .strip_prefix("seren-secrets://")
        .ok_or(ResolverError::InvalidUri(
            "uri must start with seren-secrets://",
        ))?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 {
        return Err(ResolverError::InvalidUri(
            "uri shape is seren-secrets://<vault>/<item>/<field>",
        ));
    }
    let vault_id = parse_reference_uuid(parts[0]).ok_or(ResolverError::InvalidUri("vault uuid"))?;
    let item_id = parse_reference_uuid(parts[1]).ok_or(ResolverError::InvalidUri("item uuid"))?;
    let field = parts[2];
    if field.is_empty() {
        return Err(ResolverError::InvalidUri("field name"));
    }
    if field.contains(['?', '#']) {
        return Err(ResolverError::InvalidUri(
            "field must not contain query or fragment markers",
        ));
    }
    Ok((vault_id, item_id, field.to_string()))
}

/// Accept only the canonical hyphenated RFC4122 form (case-insensitive).
/// Alternate encodings could let distinct signed uri strings name one record.
fn parse_reference_uuid(value: &str) -> Option<Uuid> {
    let uuid = Uuid::parse_str(value).ok()?;
    let canonical = uuid.hyphenated().to_string().eq_ignore_ascii_case(value)
        && uuid.get_variant() == uuid::Variant::RFC4122;
    canonical.then_some(uuid)
}

fn extract_field(content: &ItemContent, field: &str) -> Result<String, ResolverError> {
    let value = match content {
        ItemContent::Login(login) => extract_login_field(login, field),
        ItemContent::SecureNote(note) => extract_secure_note_field(note, field),
        ItemContent::ApiCredential(api) => extract_api_credential_field(api, field),
        ItemContent::Card(card) => extract_card_field(card, field),
        ItemContent::Identity(id) => extract_identity_field(id, field),
        ItemContent::Document(doc) => extract_document_field(doc, field),
        ItemContent::SshKey(key) => extract_ssh_key_field(key, field),
        ItemContent::Server(s) => extract_server_field(s, field),
        ItemContent::Database(d) => extract_database_field(d, field),
        ItemContent::BankAccount(bank) => extract_bank_account_field(bank, field),
        ItemContent::Passport(p) => extract_passport_field(p, field),
        ItemContent::DriverLicense(l) => extract_driver_license_field(l, field),
        ItemContent::CryptoWallet(w) => extract_crypto_wallet_field(w, field),
    }?;
    if value.is_empty() {
        return Err(ResolverError::UnknownField(field.to_string()));
    }
    Ok(value)
}

fn extract_identity_field(
    id: &seren_secrets_crypto::protocol::item::IdentityContent,
    field: &str,
) -> Result<String, ResolverError> {
    if let Some(value) = try_extract_identity_multi(id, field) {
        return Ok(value);
    }
    let normalized = field.to_ascii_lowercase();
    let primary_address = id.addresses.first();
    Ok(match normalized.as_str() {
        "first_name" | "given_name" => id.first_name.clone(),
        "middle_name" => id.middle_name.clone(),
        "last_name" | "family_name" | "surname" => id.last_name.clone(),
        "full_name" | "name" => join_full_name(&id.first_name, &id.middle_name, &id.last_name),
        "username" | "handle" => id.username.clone(),
        "company" | "employer" | "organization" => id.company.clone(),
        "job_title" | "title" => id.job_title.clone(),
        "gender" | "sex" => id.gender.clone(),
        "email" => id
            .emails
            .first()
            .map(|e| e.value.clone())
            .unwrap_or_default(),
        "phone" | "phone_number" | "telephone" => id
            .phones
            .first()
            .map(|p| p.value.clone())
            .unwrap_or_default(),
        "date_of_birth" | "dob" | "birthday" | "birthdate" => {
            id.date_of_birth.clone().unwrap_or_default()
        }
        "address" | "full_address" => primary_address.map(format_address).unwrap_or_default(),
        "street" | "street_address" | "address_line" => primary_address
            .map(|a| a.street.clone())
            .unwrap_or_default(),
        "city" | "locality" => primary_address.map(|a| a.city.clone()).unwrap_or_default(),
        "region" | "state" | "province" => primary_address
            .map(|a| a.region.clone())
            .unwrap_or_default(),
        "postal_code" | "zip" | "zip_code" | "postcode" => primary_address
            .map(|a| a.postal_code.clone())
            .unwrap_or_default(),
        "country" => primary_address
            .map(|a| a.country.clone())
            .unwrap_or_default(),
        "government_id" | "government_id_number" | "id_number" => id
            .government_ids
            .first()
            .map(|g| g.number.clone())
            .unwrap_or_default(),
        "passport" | "passport_number" => {
            extract_government_id_number(&id.government_ids, &["passport"]).unwrap_or_default()
        }
        "driver_license"
        | "drivers_license"
        | "driver_license_number"
        | "drivers_license_number"
        | "license_number" => {
            extract_government_id_number(&id.government_ids, &["driver", "license"])
                .unwrap_or_default()
        }
        "notes" | "note" => projected_text(&id.notes_text, &id.notes),
        other => extract_custom_field(&id.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

/// Resolve the multi-valued Identity arrays via `name[N]` index syntax
/// or `name.label` label syntax, optionally with a `.subfield` tail.
/// Returns `Some` when the field syntactically matches one of the array
/// prefixes (emails/phones/addresses/government_ids). The outer extractor
/// rejects empty values so missing selectors fail closed.
fn try_extract_identity_multi(
    id: &seren_secrets_crypto::protocol::item::IdentityContent,
    field: &str,
) -> Option<String> {
    let lower = field.to_ascii_lowercase();
    let (base, rest) = split_array_prefix(&lower)?;
    let selector = match parse_selector(rest) {
        Some(selector) => selector,
        None => return Some(String::new()),
    };
    match base {
        "emails" => Some(resolve_email(&id.emails, &selector)),
        "phones" => Some(resolve_phone(&id.phones, &selector)),
        "addresses" => Some(resolve_address(&id.addresses, &selector)),
        "government_ids" => Some(resolve_government_id(&id.government_ids, &selector)),
        _ => None,
    }
}

enum ArraySelector<'a> {
    Index {
        index: usize,
        subfield: Option<&'a str>,
    },
    Label {
        label: &'a str,
        subfield: Option<&'a str>,
    },
}

fn split_array_prefix(field: &str) -> Option<(&str, &str)> {
    for prefix in ["emails", "phones", "addresses", "government_ids"] {
        if let Some(rest) = field.strip_prefix(prefix)
            && (rest.starts_with('[') || rest.starts_with('.'))
        {
            return Some((prefix, rest));
        }
    }
    None
}

fn parse_selector(rest: &str) -> Option<ArraySelector<'_>> {
    if let Some(after_bracket) = rest.strip_prefix('[') {
        let (idx_str, tail) = after_bracket.split_once(']')?;
        let index: usize = idx_str.parse().ok()?;
        let subfield = parse_subfield(tail)?;
        Some(ArraySelector::Index { index, subfield })
    } else if let Some(after_dot) = rest.strip_prefix('.') {
        if after_dot.is_empty() {
            return None;
        }
        let (label, subfield) = match after_dot.split_once('.') {
            Some((label, sub)) => (label, Some(sub)),
            None => (after_dot, None),
        };
        Some(ArraySelector::Label { label, subfield })
    } else {
        None
    }
}

fn parse_subfield(tail: &str) -> Option<Option<&str>> {
    if tail.is_empty() {
        Some(None)
    } else {
        tail.strip_prefix('.').map(Some)
    }
}

fn resolve_email(
    entries: &[seren_secrets_crypto::protocol::item::EmailEntry],
    selector: &ArraySelector<'_>,
) -> String {
    let (entry, sub) = match selector {
        ArraySelector::Index { index, subfield } => (entries.get(*index), *subfield),
        ArraySelector::Label { label, subfield } => (
            entries.iter().find(|e| label_matches(&e.label, label)),
            *subfield,
        ),
    };
    let Some(entry) = entry else {
        return String::new();
    };
    match sub.unwrap_or("value").to_ascii_lowercase().as_str() {
        "value" | "email" | "address" => entry.value.clone(),
        "label" | "tag" => entry.label.clone(),
        _ => String::new(),
    }
}

fn resolve_phone(
    entries: &[seren_secrets_crypto::protocol::item::PhoneEntry],
    selector: &ArraySelector<'_>,
) -> String {
    let (entry, sub) = match selector {
        ArraySelector::Index { index, subfield } => (entries.get(*index), *subfield),
        ArraySelector::Label { label, subfield } => (
            entries.iter().find(|e| label_matches(&e.label, label)),
            *subfield,
        ),
    };
    let Some(entry) = entry else {
        return String::new();
    };
    match sub.unwrap_or("value").to_ascii_lowercase().as_str() {
        "value" | "number" | "phone" => entry.value.clone(),
        "label" | "tag" => entry.label.clone(),
        _ => String::new(),
    }
}

fn resolve_address(
    entries: &[seren_secrets_crypto::protocol::item::PostalAddress],
    selector: &ArraySelector<'_>,
) -> String {
    let (entry, sub) = match selector {
        ArraySelector::Index { index, subfield } => (entries.get(*index), *subfield),
        ArraySelector::Label { .. } => (None, None),
    };
    let Some(entry) = entry else {
        return String::new();
    };
    match sub.map(|s| s.to_ascii_lowercase()).as_deref().unwrap_or("") {
        "" | "full" | "full_address" | "formatted" => format_address(entry),
        "street" | "street_address" | "address_line" => entry.street.clone(),
        "city" | "locality" => entry.city.clone(),
        "region" | "state" | "province" => entry.region.clone(),
        "postal_code" | "zip" | "zip_code" | "postcode" => entry.postal_code.clone(),
        "country" => entry.country.clone(),
        _ => String::new(),
    }
}

fn resolve_government_id(
    entries: &[seren_secrets_crypto::protocol::item::GovernmentId],
    selector: &ArraySelector<'_>,
) -> String {
    let (entry, sub) = match selector {
        ArraySelector::Index { index, subfield } => (entries.get(*index), *subfield),
        ArraySelector::Label { label, subfield } => (
            entries.iter().find(|g| label_matches(&g.label, label)),
            *subfield,
        ),
    };
    let Some(entry) = entry else {
        return String::new();
    };
    match sub.unwrap_or("number").to_ascii_lowercase().as_str() {
        "number" | "value" | "id" => entry.number.clone(),
        "label" | "kind" | "type" => entry.label.clone(),
        "issuer" => entry.issuer.clone(),
        "issued_on" | "issued" => entry.issued_on.clone().unwrap_or_default(),
        "expires_on" | "expires" | "expiration" => entry.expires_on.clone().unwrap_or_default(),
        _ => String::new(),
    }
}

/// Case-insensitive label match for `name.label` selectors. The stored
/// label is broken on non-alphanumeric runs so `government_ids.passport`
/// hits a stored `"US passport"` and `emails.work` hits `"Work email"`.
/// Tokens must match in full; substring overlap (e.g. `id` against
/// `"identity"`) is intentionally rejected to keep the match predictable.
/// When the requested token matches more than one stored entry, the first
/// in iteration order wins; callers that need a different tiebreak should
/// use the index form (`name[N]`).
fn label_matches(stored: &str, requested: &str) -> bool {
    let stored = stored.to_ascii_lowercase();
    let requested = requested.to_ascii_lowercase();
    if stored == requested {
        return true;
    }
    stored
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == requested)
}

fn extract_bank_account_field(
    bank: &seren_secrets_crypto::protocol::item::BankAccountContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "bank_name" | "bank" => bank.bank_name.clone(),
        "account_holder" | "name" => bank.account_holder.clone(),
        "account_number" | "account" => bank.account_number.clone(),
        "routing_number" | "routing" | "aba" | "rtn" => bank.routing_number.clone(),
        "account_type" | "type" => bank.account_type.clone(),
        "iban" => bank.iban.clone(),
        "swift" | "bic" | "swift_code" => bank.swift.clone(),
        "branch" => bank.branch.clone(),
        "pin" => bank.pin.clone(),
        "notes" | "note" => projected_text(&bank.notes_text, &bank.notes),
        other => extract_custom_field(&bank.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_passport_field(
    p: &seren_secrets_crypto::protocol::item::PassportContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "number" | "passport_number" => p.number.clone(),
        "passport_type" | "type" => p.passport_type.clone(),
        "full_name" | "name" => p.full_name.clone(),
        "surname" | "family_name" | "last_name" => p.surname.clone(),
        "given_names" | "first_name" | "given_name" => p.given_names.clone(),
        "nationality" => p.nationality.clone(),
        "date_of_birth" | "dob" | "birthday" | "birthdate" => {
            p.date_of_birth.clone().unwrap_or_default()
        }
        "place_of_birth" => p.place_of_birth.clone(),
        "gender" | "sex" => p.gender.clone(),
        "issuing_country" | "country" => p.issuing_country.clone(),
        "issuing_authority" | "authority" => p.issuing_authority.clone(),
        "issued_on" | "issue_date" | "issued" => p.issued_on.clone().unwrap_or_default(),
        "expires_on" | "expiry" | "expiration" | "expires" => {
            p.expires_on.clone().unwrap_or_default()
        }
        "notes" | "note" => projected_text(&p.notes_text, &p.notes),
        other => extract_custom_field(&p.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_driver_license_field(
    l: &seren_secrets_crypto::protocol::item::DriverLicenseContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    let address = l.address.as_ref();
    Ok(match normalized.as_str() {
        "number" | "license_number" => l.number.clone(),
        "full_name" | "name" => l.full_name.clone(),
        "date_of_birth" | "dob" | "birthday" | "birthdate" => {
            l.date_of_birth.clone().unwrap_or_default()
        }
        "gender" | "sex" => l.gender.clone(),
        "address" | "full_address" => address.map(format_address).unwrap_or_default(),
        "city" => address.map(|a| a.city.clone()).unwrap_or_default(),
        "region" | "state" | "province" => address.map(|a| a.region.clone()).unwrap_or_default(),
        "postal_code" | "zip" | "postcode" => {
            address.map(|a| a.postal_code.clone()).unwrap_or_default()
        }
        "country" => l.country.clone(),
        "state_jurisdiction" => l.state.clone(),
        "license_class" | "class" => l.license_class.clone(),
        "conditions" | "restrictions" | "endorsements" => l.conditions.clone(),
        "issued_on" | "issue_date" | "issued" => l.issued_on.clone().unwrap_or_default(),
        "expires_on" | "expiry" | "expiration" | "expires" => {
            l.expires_on.clone().unwrap_or_default()
        }
        "notes" | "note" => projected_text(&l.notes_text, &l.notes),
        other => extract_custom_field(&l.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_crypto_wallet_field(
    w: &seren_secrets_crypto::protocol::item::CryptoWalletContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "wallet_name" | "name" => w.wallet_name.clone(),
        "network" | "chain" => w.network.clone(),
        "seed_phrase" | "mnemonic" | "recovery_phrase" => w.seed_phrase.clone(),
        "private_key" | "secret_key" => w.private_key.clone(),
        "password" | "passphrase" => w.password.clone(),
        "derivation_path" | "path" => w.derivation_path.clone(),
        "address" => w
            .addresses
            .first()
            .map(|a| a.address.clone())
            .unwrap_or_default(),
        "notes" | "note" => projected_text(&w.notes_text, &w.notes),
        other => extract_custom_field(&w.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_server_field(
    s: &seren_secrets_crypto::protocol::item::ServerContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "hostname" | "host" | "server" => s.hostname.clone(),
        "port" => s.port.map(|p| p.to_string()).unwrap_or_default(),
        "protocol" | "scheme" => s.protocol.clone(),
        "username" | "user" => s.username.clone(),
        "password" => s.password.clone(),
        "ssh_key_reference" | "key_reference" | "ssh_key" => s.ssh_key_reference.clone(),
        "admin_console_url" | "admin_url" | "console" => s.admin_console_url.clone(),
        "notes" | "note" => projected_text(&s.notes_text, &s.notes),
        other => extract_custom_field(&s.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_database_field(
    d: &seren_secrets_crypto::protocol::item::DatabaseContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "database_type" | "type" | "engine" => d.database_type.clone(),
        "server" | "host" | "hostname" => d.server.clone(),
        "port" => d.port.map(|p| p.to_string()).unwrap_or_default(),
        "database_name" | "database" | "db" => d.database_name.clone(),
        "username" | "user" => d.username.clone(),
        "password" => d.password.clone(),
        "sid" => d.sid.clone(),
        "schema" => d.schema.clone(),
        "notes" | "note" => projected_text(&d.notes_text, &d.notes),
        other => extract_custom_field(&d.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_government_id_number(
    ids: &[seren_secrets_crypto::protocol::item::GovernmentId],
    label_terms: &[&str],
) -> Option<String> {
    ids.iter()
        .find(|id| {
            let label = id.label.to_ascii_lowercase();
            label_terms.iter().all(|term| label.contains(term))
        })
        .map(|id| id.number.clone())
}

fn join_full_name(first: &str, middle: &str, last: &str) -> String {
    [first, middle, last]
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_address(address: &seren_secrets_crypto::protocol::item::PostalAddress) -> String {
    [
        address.street.as_str(),
        address.city.as_str(),
        address.region.as_str(),
        address.postal_code.as_str(),
        address.country.as_str(),
    ]
    .iter()
    .filter(|part| !part.is_empty())
    .copied()
    .collect::<Vec<_>>()
    .join(", ")
}

fn extract_card_field(
    card: &seren_secrets_crypto::protocol::item::CardContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "number" | "card_number" | "pan" | "account_number" => card.number.clone(),
        "cardholder" | "cardholder_name" | "name_on_card" | "name" => card.cardholder_name.clone(),
        "brand" | "network" | "card_brand" => card.brand.clone(),
        "expiry" | "expires" | "exp" | "expiration" | "expiration_date" => card.expiry.clone(),
        "cvv" | "cvc" | "cvv2" | "security_code" => card.cvv.clone(),
        "pin" => card.pin.clone(),
        "billing_address" => card
            .billing_address
            .as_ref()
            .map(format_address)
            .unwrap_or_default(),
        "billing_street" => card
            .billing_address
            .as_ref()
            .map(|a| a.street.clone())
            .unwrap_or_default(),
        "billing_city" => card
            .billing_address
            .as_ref()
            .map(|a| a.city.clone())
            .unwrap_or_default(),
        "billing_region" | "billing_state" | "billing_province" => card
            .billing_address
            .as_ref()
            .map(|a| a.region.clone())
            .unwrap_or_default(),
        "billing_postal_code" | "billing_zip" | "billing_zip_code" => card
            .billing_address
            .as_ref()
            .map(|a| a.postal_code.clone())
            .unwrap_or_default(),
        "billing_country" => card
            .billing_address
            .as_ref()
            .map(|a| a.country.clone())
            .unwrap_or_default(),
        "notes" | "note" => projected_text(&card.notes_text, &card.notes),
        other => extract_custom_field(&card.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_ssh_key_field(
    key: &seren_secrets_crypto::protocol::item::SshKeyContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "private_key" | "private" | "private_key_pem" | "key" => key.private_key.clone(),
        "public_key" | "public" | "authorized_key" => key.public_key.clone(),
        "passphrase" | "password" => key.passphrase.clone(),
        "fingerprint" => key.fingerprint.clone(),
        "key_type" | "type" | "algorithm" => key.key_type.clone(),
        "notes" | "note" => projected_text(&key.notes_text, &key.notes),
        other => extract_custom_field(&key.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_document_field(
    doc: &seren_secrets_crypto::protocol::item::DocumentContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "filename" | "file_name" | "name" => doc.filename.clone(),
        "content_type" | "mime" | "mime_type" | "media_type" => doc.content_type.clone(),
        "size" | "size_bytes" | "byte_size" => {
            doc.size_bytes.map(|n| n.to_string()).unwrap_or_default()
        }
        "alt_text" | "alt" | "description" => doc.alt_text.clone(),
        "attachment_uri" | "attachment" | "uri" | "url" => doc.attachment_uri.clone(),
        "notes" | "note" => projected_text(&doc.notes_text, &doc.notes),
        other => extract_custom_field(&doc.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_login_field(login: &LoginContent, field: &str) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "username" | "user" => login.username.clone(),
        "password" | "pass" => login.password.clone(),
        "notes" | "note" => projected_text(&login.notes_text, &login.notes),
        "url" | "urls" => login
            .urls
            .first()
            .map(|u| u.url.clone())
            .unwrap_or_default(),
        "totp" | "otp" | "totp_secret" | "secret_base32" => login
            .totp
            .as_ref()
            .map(|t| t.secret_base32.clone())
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
        other => extract_custom_field(&login.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_secure_note_field(
    note: &SecureNoteContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "body" | "note" | "notes" => projected_text(&note.body_text, &note.body),
        other => extract_custom_field(&note.custom_fields, other)
            .ok_or_else(|| ResolverError::UnknownField(field.into()))?,
    })
}

fn extract_api_credential_field(
    api: &ApiCredentialContent,
    field: &str,
) -> Result<String, ResolverError> {
    let normalized = field.to_ascii_lowercase();
    Ok(match normalized.as_str() {
        "primary" | "primary_value" | "value" | "key" => api.primary_value.clone(),
        "secondary" | "secondary_value" | "secret" => api.secondary_value.clone(),
        "notes" | "note" => projected_text(&api.notes_text, &api.notes),
        other => {
            // Header names are case-insensitive (per RFC 7230). Match the
            // request field against the stored header names case-insensitively
            // before falling back to custom fields.
            if let Some(v) = api
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(other))
                .map(|(_, v)| v)
            {
                v.clone()
            } else {
                extract_custom_field(&api.custom_fields, other)
                    .ok_or_else(|| ResolverError::UnknownField(field.into()))?
            }
        }
    })
}

/// Return the cached plain-text companion when present; otherwise re-derive
/// it from the canonical ProseMirror doc. The doc is the source of truth, so
/// a stale or absent `_text` field must not produce silently empty output
/// when the doc has content.
fn projected_text(cached: &str, doc: &seren_secrets_crypto::prose::ProseDoc) -> String {
    if !cached.is_empty() {
        return cached.to_string();
    }
    doc.plain_text()
}

fn extract_custom_field(
    fields: &[seren_secrets_crypto::protocol::item::CustomField],
    name: &str,
) -> Option<String> {
    // Match by name first (case-insensitive). If nothing matches by
    // name, fall back to matching by FieldPurpose so an agent asking
    // for the generic alias ("password", "private_key", etc.) finds
    // the right field even when the user renamed it.
    if let Some(by_name) = fields
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case(name))
        .map(|f| f.value.clone())
    {
        return Some(by_name);
    }
    let purpose_match = match name.to_ascii_lowercase().as_str() {
        "username" | "user" => Some(seren_secrets_crypto::protocol::item::FieldPurpose::Username),
        "password" | "pass" => Some(seren_secrets_crypto::protocol::item::FieldPurpose::Password),
        "notes" | "note" => Some(seren_secrets_crypto::protocol::item::FieldPurpose::Notes),
        "otp" | "totp" | "totp_secret" => {
            Some(seren_secrets_crypto::protocol::item::FieldPurpose::Otp)
        }
        "private_key" | "private" => {
            Some(seren_secrets_crypto::protocol::item::FieldPurpose::PrivateKey)
        }
        "public_key" | "public" => {
            Some(seren_secrets_crypto::protocol::item::FieldPurpose::PublicKey)
        }
        "card_number" | "pan" => {
            Some(seren_secrets_crypto::protocol::item::FieldPurpose::CardNumber)
        }
        "cvv" | "cvc" | "cvv2" | "security_code" => {
            Some(seren_secrets_crypto::protocol::item::FieldPurpose::Cvv)
        }
        "pin" => Some(seren_secrets_crypto::protocol::item::FieldPurpose::Pin),
        _ => None,
    }?;
    fields
        .iter()
        .find(|f| f.purpose == Some(purpose_match))
        .map(|f| f.value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seren_secrets_crypto::{ZeroizableBTreeMap, ZeroizableJson};

    #[test]
    fn parses_seren_secrets_uri() {
        let v = Uuid::new_v4();
        let i = Uuid::new_v4();
        let (vp, ip, field) =
            parse_seren_secrets_uri(&format!("seren-secrets://{v}/{i}/password")).unwrap();
        assert_eq!(vp, v);
        assert_eq!(ip, i);
        assert_eq!(field, "password");
    }

    #[test]
    fn rejects_wrong_scheme() {
        let err = parse_seren_secrets_uri("op://a/b/c").unwrap_err();
        assert!(matches!(err, ResolverError::InvalidUri(_)));
    }

    #[test]
    fn accepts_uppercase_hyphenated_uuids() {
        // Parity with the desktop reference validator: canonical hyphenated
        // form is matched case-insensitively.
        let v = Uuid::new_v4().to_string().to_uppercase();
        let i = Uuid::new_v4().to_string().to_uppercase();
        let (vp, ip, field) =
            parse_seren_secrets_uri(&format!("seren-secrets://{v}/{i}/password")).unwrap();
        assert_eq!(vp.to_string().to_uppercase(), v);
        assert_eq!(ip.to_string().to_uppercase(), i);
        assert_eq!(field, "password");
    }

    #[test]
    fn rejects_non_canonical_uuid_encodings() {
        let v = Uuid::new_v4();
        let i = Uuid::new_v4();
        // Simple (un-hyphenated) form.
        let uri = format!("seren-secrets://{}/{i}/password", v.simple());
        assert!(matches!(
            parse_seren_secrets_uri(&uri).unwrap_err(),
            ResolverError::InvalidUri(_)
        ));
        // Braced form.
        let uri = format!("seren-secrets://{}/{i}/password", v.braced());
        assert!(matches!(
            parse_seren_secrets_uri(&uri).unwrap_err(),
            ResolverError::InvalidUri(_)
        ));
        // URN form.
        let uri = format!("seren-secrets://{}/{i}/password", v.urn());
        assert!(matches!(
            parse_seren_secrets_uri(&uri).unwrap_err(),
            ResolverError::InvalidUri(_)
        ));
    }

    #[test]
    fn accepts_standard_variant_uuid_versions_beyond_v5() {
        let mut v7_bytes = [0x11; 16];
        v7_bytes[6] = (v7_bytes[6] & 0x0f) | 0x70;
        v7_bytes[8] = (v7_bytes[8] & 0x3f) | 0x80;
        let v = Uuid::from_bytes(v7_bytes);
        let i = Uuid::new_v4();

        let (vp, ip, field) =
            parse_seren_secrets_uri(&format!("seren-secrets://{v}/{i}/password")).unwrap();

        assert_eq!(vp, v);
        assert_eq!(ip, i);
        assert_eq!(field, "password");
    }

    #[test]
    fn rejects_non_standard_variant_uuid_values() {
        let i = Uuid::new_v4();
        let uri = format!("seren-secrets://{}/{i}/password", Uuid::nil());
        assert!(matches!(
            parse_seren_secrets_uri(&uri).unwrap_err(),
            ResolverError::InvalidUri(_)
        ));

        let uri = format!("seren-secrets://{}/{i}/password", Uuid::max());
        assert!(matches!(
            parse_seren_secrets_uri(&uri).unwrap_err(),
            ResolverError::InvalidUri(_)
        ));
    }

    #[test]
    fn rejects_query_fragment_extra_segments_and_whitespace() {
        let v = Uuid::new_v4();
        let i = Uuid::new_v4();
        for bad in [
            format!("seren-secrets://{v}/{i}/password?x=1"),
            format!("seren-secrets://{v}/{i}/password#frag"),
            format!("seren-secrets://{v}/{i}/password/extra"),
            format!("seren-secrets://{v}/{i}/pass word"),
            format!("seren-secrets://{v}/{i}/password "),
            format!(" seren-secrets://{v}/{i}/password"),
        ] {
            assert!(
                matches!(
                    parse_seren_secrets_uri(&bad).unwrap_err(),
                    ResolverError::InvalidUri(_)
                ),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_empty_field_name() {
        let v = Uuid::new_v4();
        let i = Uuid::new_v4();
        let err = parse_seren_secrets_uri(&format!("seren-secrets://{v}/{i}/")).unwrap_err();
        assert!(matches!(err, ResolverError::InvalidUri(_)));
    }

    #[test]
    fn resolve_payload_decrypts_body_through_item_content_key() {
        let vault_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let kem = IdentityKemKeypair::generate();
        let vault_key = seren_secrets_crypto::protocol::vault::generate_vault_key();
        let content_key = seren_secrets_crypto::protocol::item::generate_item_content_key();
        let content = ItemContent::Login(LoginContent {
            username: "alice".into(),
            password: "hunter2".into(),
            urls: vec!["https://example.com".into()],
            totp: None,
            notes: seren_secrets_crypto::prose::ProseDoc::empty(),
            notes_text: String::new(),
            custom_fields: vec![],
            password_history: Vec::new(),
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        let wrapped_vault_key = seren_secrets_crypto::protocol::vault::wrap_vault_key_for_identity(
            &vault_key,
            &kem.public,
        );
        let content_key_wrap = seren_secrets_crypto::protocol::item::wrap_item_content_key(
            &vault_key,
            item_id.as_bytes(),
            &content_key,
        );
        let content_ciphertext =
            seren_secrets_crypto::protocol::item::encrypt_item_with_content_key(
                &content_key,
                item_id.as_bytes(),
                &content,
            )
            .expect("content encrypts");
        let payload = ResolveResponseBody {
            vault_id,
            item_id,
            field_name: "password".into(),
            content_ciphertext: B64.encode(content_ciphertext),
            content_key_wrap: B64.encode(content_key_wrap),
            wrapped_vault_key: B64.encode(wrapped_vault_key),
        };

        let decrypted =
            decrypt_resolve_payload(&payload, vault_id, item_id, "password", &kem.private)
                .expect("payload decrypts");

        assert_eq!(extract_field(&decrypted, "password").unwrap(), "hunter2");
    }

    #[test]
    fn resolve_payload_rejects_content_key_wrap_for_other_item() {
        let vault_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let other_item_id = Uuid::new_v4();
        let kem = IdentityKemKeypair::generate();
        let vault_key = seren_secrets_crypto::protocol::vault::generate_vault_key();
        let content_key = seren_secrets_crypto::protocol::item::generate_item_content_key();
        let content = ItemContent::SecureNote(SecureNoteContent {
            body: seren_secrets_crypto::prose::ProseDoc::empty(),
            body_text: "private".into(),
            custom_fields: vec![],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        let wrapped_vault_key = seren_secrets_crypto::protocol::vault::wrap_vault_key_for_identity(
            &vault_key,
            &kem.public,
        );
        let content_key_wrap = seren_secrets_crypto::protocol::item::wrap_item_content_key(
            &vault_key,
            other_item_id.as_bytes(),
            &content_key,
        );
        let content_ciphertext =
            seren_secrets_crypto::protocol::item::encrypt_item_with_content_key(
                &content_key,
                item_id.as_bytes(),
                &content,
            )
            .expect("content encrypts");
        let payload = ResolveResponseBody {
            vault_id,
            item_id,
            field_name: "body".into(),
            content_ciphertext: B64.encode(content_ciphertext),
            content_key_wrap: B64.encode(content_key_wrap),
            wrapped_vault_key: B64.encode(wrapped_vault_key),
        };

        let err =
            decrypt_resolve_payload(&payload, vault_id, item_id, "body", &kem.private).unwrap_err();

        assert!(matches!(err, ResolverError::Crypto(_)));
    }

    #[test]
    fn extracts_login_fields() {
        let (notes_doc, notes_text) = seren_secrets_crypto::prose::from_plaintext("test");
        let login = LoginContent {
            username: "alice".into(),
            password: "hunter2".into(),
            urls: vec!["https://example.com".into()],
            totp: Some(seren_secrets_crypto::protocol::item::TotpConfig {
                secret_base32: "JBSWY3DPEHPK3PXP".into(),
                algorithm: seren_secrets_crypto::protocol::item::TotpAlgorithm::Sha1,
                digits: 6,
                period_seconds: 30,
            }),
            notes: notes_doc,
            notes_text,
            custom_fields: vec![seren_secrets_crypto::protocol::item::CustomField {
                name: "recovery_code".into(),
                kind: seren_secrets_crypto::protocol::item::CustomFieldKind::Concealed,
                value: "ABC-DEF-GHI".into(),
                purpose: None,

                ..Default::default()
            }],
            password_history: Vec::new(),
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        };
        let content = ItemContent::Login(login);
        assert_eq!(extract_field(&content, "username").unwrap(), "alice");
        assert_eq!(extract_field(&content, "password").unwrap(), "hunter2");
        assert_eq!(
            extract_field(&content, "url").unwrap(),
            "https://example.com"
        );
        assert_eq!(extract_field(&content, "totp").unwrap(), "JBSWY3DPEHPK3PXP");
        assert_eq!(extract_field(&content, "notes").unwrap(), "test");
        assert_eq!(
            extract_field(&content, "recovery_code").unwrap(),
            "ABC-DEF-GHI"
        );
        let err = extract_field(&content, "no-such-field").unwrap_err();
        assert!(matches!(err, ResolverError::UnknownField(_)));
    }

    #[test]
    fn extracts_secure_note_body() {
        let (body_doc, body_text) = seren_secrets_crypto::prose::from_plaintext("private text");
        let note = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            custom_fields: vec![],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        assert_eq!(extract_field(&note, "body").unwrap(), "private text");
        assert_eq!(extract_field(&note, "notes").unwrap(), "private text");
    }

    #[test]
    fn notes_field_falls_back_to_canonical_doc_when_text_is_stale() {
        // The doc is canonical: if notes_text was not refreshed by the
        // writer but the ProseMirror tree carries content, agent runtimes
        // must still receive the visible text rather than an empty string.
        let (notes_doc, _) = seren_secrets_crypto::prose::from_plaintext("rotate weekly");
        let login = LoginContent {
            username: "alice".into(),
            password: "hunter2".into(),
            urls: vec![],
            totp: None,
            notes: notes_doc,
            notes_text: String::new(),
            custom_fields: vec![],
            password_history: Vec::new(),
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        };
        let content = ItemContent::Login(login);
        assert_eq!(extract_field(&content, "notes").unwrap(), "rotate weekly");

        let note = ItemContent::SecureNote(SecureNoteContent {
            body: seren_secrets_crypto::prose::from_plaintext("private").0,
            body_text: String::new(),
            custom_fields: vec![],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        assert_eq!(extract_field(&note, "body").unwrap(), "private");
    }

    #[test]
    fn custom_field_purpose_fallback_edge_cases() {
        // Pins the three cases the contract docs describe so future
        // changes to extract_custom_field cannot quietly drift:
        //   1. purpose set, no name match -> purpose fallback resolves.
        //   2. name match wins even when another field carries the
        //      matching purpose (name beats purpose, deliberately).
        //   3. multiple fields with the same purpose -> first one
        //      wins; iteration order is the array order.
        use seren_secrets_crypto::protocol::item::{
            ApiCredentialContent, ApiCredentialKind, CustomField, CustomFieldKind, FieldPurpose,
        };

        // Case 1: only purpose set, no field named "password".
        let only_purpose = ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::ApiKey,
            primary_value: String::new(),
            secondary_value: String::new(),
            headers: ZeroizableBTreeMap::default(),
            rotation: None,
            notes: seren_secrets_crypto::prose::ProseDoc::empty(),
            notes_text: String::new(),
            custom_fields: vec![CustomField {
                name: "App Secret".into(),
                kind: CustomFieldKind::Concealed,
                value: "from-purpose".into(),
                purpose: Some(FieldPurpose::Password),

                ..Default::default()
            }],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        assert_eq!(
            extract_field(&only_purpose, "password").unwrap(),
            "from-purpose"
        );

        // Case 2: a misleadingly named field with a wrong purpose
        // still wins by name. Documented precedence: name beats
        // purpose.
        let name_beats_purpose = ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::ApiKey,
            primary_value: String::new(),
            secondary_value: String::new(),
            headers: ZeroizableBTreeMap::default(),
            rotation: None,
            notes: seren_secrets_crypto::prose::ProseDoc::empty(),
            notes_text: String::new(),
            custom_fields: vec![
                CustomField {
                    name: "Password".into(),
                    kind: CustomFieldKind::String,
                    value: "named-password".into(),
                    purpose: Some(FieldPurpose::Username),

                    ..Default::default()
                },
                CustomField {
                    name: "Real Secret".into(),
                    kind: CustomFieldKind::Concealed,
                    value: "tagged-password".into(),
                    purpose: Some(FieldPurpose::Password),

                    ..Default::default()
                },
            ],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        assert_eq!(
            extract_field(&name_beats_purpose, "password").unwrap(),
            "named-password"
        );

        // Case 3: two fields with the same purpose, first one wins.
        let two_with_same_purpose = ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::ApiKey,
            primary_value: String::new(),
            secondary_value: String::new(),
            headers: ZeroizableBTreeMap::default(),
            rotation: None,
            notes: seren_secrets_crypto::prose::ProseDoc::empty(),
            notes_text: String::new(),
            custom_fields: vec![
                CustomField {
                    name: "Token A".into(),
                    kind: CustomFieldKind::Concealed,
                    value: "first".into(),
                    purpose: Some(FieldPurpose::Password),

                    ..Default::default()
                },
                CustomField {
                    name: "Token B".into(),
                    kind: CustomFieldKind::Concealed,
                    value: "second".into(),
                    purpose: Some(FieldPurpose::Password),

                    ..Default::default()
                },
            ],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        assert_eq!(
            extract_field(&two_with_same_purpose, "password").unwrap(),
            "first"
        );
    }

    #[test]
    fn custom_field_purpose_lets_resolver_dispatch_generically() {
        // An ApiCredential whose custom_fields carry a purpose tag should
        // be resolvable by the alias even if the field name is unusual.
        // This is the path 1Password users get when a foreign export
        // names a password field "Secret" rather than "password".
        use seren_secrets_crypto::protocol::item::{
            ApiCredentialContent, ApiCredentialKind, CustomField, CustomFieldKind, FieldPurpose,
        };
        let api = ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::ApiKey,
            primary_value: String::new(),
            secondary_value: String::new(),
            headers: ZeroizableBTreeMap::default(),
            rotation: None,
            notes: seren_secrets_crypto::prose::ProseDoc::empty(),
            notes_text: String::new(),
            custom_fields: vec![
                CustomField {
                    name: "Secret".into(),
                    kind: CustomFieldKind::Concealed,
                    value: "hunter2".into(),
                    purpose: Some(FieldPurpose::Password),

                    ..Default::default()
                },
                CustomField {
                    name: "API token".into(),
                    kind: CustomFieldKind::Concealed,
                    value: "sk_live".into(),
                    purpose: None,

                    ..Default::default()
                },
            ],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        // Direct name lookup still wins when the name matches:
        assert_eq!(extract_field(&api, "API token").unwrap(), "sk_live");
        // Generic alias falls back to the purpose hint:
        assert_eq!(extract_field(&api, "password").unwrap(), "hunter2");
    }

    #[test]
    fn extracts_api_credential() {
        let api = ItemContent::ApiCredential(ApiCredentialContent {
            kind: seren_secrets_crypto::protocol::item::ApiCredentialKind::ApiKey,
            primary_value: "AKIA1234".into(),
            secondary_value: "secret-key".into(),
            headers: ZeroizableBTreeMap(std::collections::BTreeMap::from([(
                "X-API-Key".into(),
                "AKIA1234".into(),
            )])),
            rotation: None,
            notes: seren_secrets_crypto::prose::ProseDoc::empty(),
            notes_text: String::new(),
            custom_fields: vec![],
            raw_import: ZeroizableJson::default(),

            ..Default::default()
        });
        assert_eq!(extract_field(&api, "primary_value").unwrap(), "AKIA1234");
        assert_eq!(extract_field(&api, "secondary").unwrap(), "secret-key");
        assert_eq!(extract_field(&api, "X-API-Key").unwrap(), "AKIA1234");
    }

    #[test]
    fn extracts_identity_fields_with_aliases() {
        use seren_secrets_crypto::protocol::item::{GovernmentId, IdentityContent, PostalAddress};
        let id = ItemContent::Identity(IdentityContent {
            first_name: "Ada".into(),
            middle_name: "Augusta".into(),
            last_name: "Lovelace".into(),
            emails: vec![seren_secrets_crypto::protocol::item::EmailEntry {
                label: String::new(),
                value: "ada@example.com".into(),
            }],
            phones: vec![seren_secrets_crypto::protocol::item::PhoneEntry {
                label: String::new(),
                value: "+44-20-0000-0000".into(),
            }],
            date_of_birth: Some("1815-12-10".into()),
            addresses: vec![PostalAddress {
                street: "1 Analytical Way".into(),
                city: "London".into(),
                region: "England".into(),
                postal_code: "EC1A".into(),
                country: "UK".into(),
            }],
            government_ids: vec![
                GovernmentId {
                    label: "UK passport".into(),
                    number: "P1234567".into(),
                    issued_on: None,
                    expires_on: None,
                    issuer: "HM Passport Office".into(),
                },
                GovernmentId {
                    label: "Driver license".into(),
                    number: "D7654321".into(),
                    issued_on: None,
                    expires_on: None,
                    issuer: "DVLA".into(),
                },
            ],
            ..Default::default()
        });
        assert_eq!(extract_field(&id, "first_name").unwrap(), "Ada");
        assert_eq!(extract_field(&id, "given_name").unwrap(), "Ada");
        assert_eq!(extract_field(&id, "surname").unwrap(), "Lovelace");
        assert_eq!(
            extract_field(&id, "full_name").unwrap(),
            "Ada Augusta Lovelace"
        );
        // Case-insensitive matching.
        assert_eq!(extract_field(&id, "Email").unwrap(), "ada@example.com");
        assert_eq!(
            extract_field(&id, "phone_number").unwrap(),
            "+44-20-0000-0000"
        );
        assert_eq!(extract_field(&id, "dob").unwrap(), "1815-12-10");
        assert_eq!(extract_field(&id, "birthday").unwrap(), "1815-12-10");
        assert_eq!(extract_field(&id, "street").unwrap(), "1 Analytical Way");
        assert_eq!(
            extract_field(&id, "address").unwrap(),
            "1 Analytical Way, London, England, EC1A, UK"
        );
        assert_eq!(extract_field(&id, "city").unwrap(), "London");
        assert_eq!(extract_field(&id, "state").unwrap(), "England");
        assert_eq!(extract_field(&id, "zip").unwrap(), "EC1A");
        assert_eq!(extract_field(&id, "country").unwrap(), "UK");
        assert_eq!(extract_field(&id, "government_id").unwrap(), "P1234567");
        assert_eq!(extract_field(&id, "passport_number").unwrap(), "P1234567");
        assert_eq!(
            extract_field(&id, "driver_license_number").unwrap(),
            "D7654321"
        );
    }

    #[test]
    fn extracts_identity_multi_value_arrays() {
        use seren_secrets_crypto::protocol::item::{
            EmailEntry, GovernmentId, IdentityContent, PhoneEntry, PostalAddress,
        };
        let id = ItemContent::Identity(IdentityContent {
            emails: vec![
                EmailEntry {
                    label: "Work".into(),
                    value: "ada@work.example".into(),
                },
                EmailEntry {
                    label: "Personal".into(),
                    value: "ada@home.example".into(),
                },
            ],
            phones: vec![
                PhoneEntry {
                    label: "Mobile".into(),
                    value: "+1-555-0100".into(),
                },
                PhoneEntry {
                    label: "Office".into(),
                    value: "+1-555-0199".into(),
                },
            ],
            addresses: vec![
                PostalAddress {
                    street: "1 Lane".into(),
                    city: "Cambridge".into(),
                    region: "MA".into(),
                    postal_code: "02139".into(),
                    country: "USA".into(),
                },
                PostalAddress {
                    street: "2 Crescent".into(),
                    city: "London".into(),
                    region: "England".into(),
                    postal_code: "EC1A".into(),
                    country: "UK".into(),
                },
            ],
            government_ids: vec![
                GovernmentId {
                    label: "US passport".into(),
                    number: "P9999".into(),
                    issued_on: Some("2020-01-01".into()),
                    expires_on: Some("2030-01-01".into()),
                    issuer: "US Dept of State".into(),
                },
                GovernmentId {
                    label: "UK driver license".into(),
                    number: "D5555".into(),
                    issued_on: None,
                    expires_on: None,
                    issuer: "DVLA".into(),
                },
            ],
            ..Default::default()
        });
        // Index selector defaults to the natural value field.
        assert_eq!(extract_field(&id, "emails[0]").unwrap(), "ada@work.example");
        assert_eq!(extract_field(&id, "emails[1]").unwrap(), "ada@home.example");
        assert_eq!(extract_field(&id, "phones[0]").unwrap(), "+1-555-0100");
        assert_eq!(extract_field(&id, "phones[1]").unwrap(), "+1-555-0199");
        // Labeled selector is case-insensitive and matches by token.
        assert_eq!(
            extract_field(&id, "emails.work").unwrap(),
            "ada@work.example"
        );
        assert_eq!(
            extract_field(&id, "emails.PERSONAL").unwrap(),
            "ada@home.example"
        );
        assert_eq!(extract_field(&id, "phones.mobile").unwrap(), "+1-555-0100");
        assert_eq!(extract_field(&id, "phones.office").unwrap(), "+1-555-0199");
        // Subfield drill-down.
        assert_eq!(extract_field(&id, "emails[0].label").unwrap(), "Work");
        assert_eq!(extract_field(&id, "emails.work.label").unwrap(), "Work");
        assert_eq!(extract_field(&id, "phones[0].label").unwrap(), "Mobile");
        // Addresses by index, with subfield.
        assert_eq!(
            extract_field(&id, "addresses[0]").unwrap(),
            "1 Lane, Cambridge, MA, 02139, USA"
        );
        assert_eq!(extract_field(&id, "addresses[1].city").unwrap(), "London");
        assert_eq!(
            extract_field(&id, "addresses[1].postal_code").unwrap(),
            "EC1A"
        );
        // Government ids: index defaults to number; label tokens match.
        assert_eq!(extract_field(&id, "government_ids[0]").unwrap(), "P9999");
        assert_eq!(
            extract_field(&id, "government_ids[0].label").unwrap(),
            "US passport"
        );
        assert_eq!(
            extract_field(&id, "government_ids[0].issued_on").unwrap(),
            "2020-01-01"
        );
        assert_eq!(
            extract_field(&id, "government_ids.passport").unwrap(),
            "P9999"
        );
        assert_eq!(
            extract_field(&id, "government_ids.license.issuer").unwrap(),
            "DVLA"
        );
        // Missing or malformed selectors fail closed.
        for field in [
            "emails[5]",
            "emails.nonsense",
            "emails[0]garbage",
            "emails[]",
            "addresses[0]garbage",
        ] {
            assert!(matches!(
                extract_field(&id, field),
                Err(ResolverError::UnknownField(_))
            ));
        }
    }

    #[test]
    fn extracts_card_fields_with_aliases() {
        use seren_secrets_crypto::protocol::item::{CardContent, PostalAddress};
        let card = ItemContent::Card(CardContent {
            cardholder_name: "Alice Example".into(),
            number: "4242424242424242".into(),
            brand: "Visa".into(),
            expiry: "12/30".into(),
            cvv: "123".into(),
            pin: "9999".into(),
            billing_address: Some(PostalAddress {
                street: "2 Billing Rd".into(),
                city: "Seattle".into(),
                region: "WA".into(),
                postal_code: "98101".into(),
                country: "USA".into(),
            }),
            ..Default::default()
        });
        assert_eq!(extract_field(&card, "pan").unwrap(), "4242424242424242");
        assert_eq!(
            extract_field(&card, "card_number").unwrap(),
            "4242424242424242"
        );
        assert_eq!(
            extract_field(&card, "name_on_card").unwrap(),
            "Alice Example"
        );
        assert_eq!(extract_field(&card, "card_brand").unwrap(), "Visa");
        assert_eq!(extract_field(&card, "expiration").unwrap(), "12/30");
        assert_eq!(extract_field(&card, "cvc").unwrap(), "123");
        assert_eq!(extract_field(&card, "pin").unwrap(), "9999");
        assert_eq!(
            extract_field(&card, "billing_address").unwrap(),
            "2 Billing Rd, Seattle, WA, 98101, USA"
        );
        assert_eq!(
            extract_field(&card, "billing_street").unwrap(),
            "2 Billing Rd"
        );
        assert_eq!(extract_field(&card, "billing_city").unwrap(), "Seattle");
        assert_eq!(extract_field(&card, "billing_zip").unwrap(), "98101");
        assert_eq!(extract_field(&card, "BILLING_COUNTRY").unwrap(), "USA");
    }

    #[test]
    fn extracts_ssh_key_fields_with_aliases() {
        use seren_secrets_crypto::protocol::item::SshKeyContent;
        let key = ItemContent::SshKey(SshKeyContent {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\n...".into(),
            public_key: "ssh-ed25519 AAAA...".into(),
            passphrase: "p4ss".into(),
            fingerprint: "SHA256:abc".into(),
            key_type: "ed25519".into(),
            ..Default::default()
        });
        assert!(
            extract_field(&key, "private_key")
                .unwrap()
                .starts_with("-----BEGIN")
        );
        assert!(
            extract_field(&key, "private_key_pem")
                .unwrap()
                .starts_with("-----BEGIN")
        );
        assert_eq!(
            extract_field(&key, "public_key").unwrap(),
            "ssh-ed25519 AAAA..."
        );
        assert_eq!(
            extract_field(&key, "authorized_key").unwrap(),
            "ssh-ed25519 AAAA..."
        );
        assert_eq!(extract_field(&key, "passphrase").unwrap(), "p4ss");
        assert_eq!(extract_field(&key, "fingerprint").unwrap(), "SHA256:abc");
        assert_eq!(extract_field(&key, "algorithm").unwrap(), "ed25519");
    }

    #[test]
    fn extracts_document_fields_with_aliases() {
        use seren_secrets_crypto::protocol::item::DocumentContent;
        let doc = ItemContent::Document(DocumentContent {
            filename: "passport.pdf".into(),
            content_type: "application/pdf".into(),
            size_bytes: Some(12_345),
            alt_text: "passport scan".into(),
            attachment_uri: "seren-secrets://attachment/00000000-0000-0000-0000-000000000000"
                .into(),
            ..Default::default()
        });
        assert_eq!(extract_field(&doc, "filename").unwrap(), "passport.pdf");
        assert_eq!(extract_field(&doc, "file_name").unwrap(), "passport.pdf");
        assert_eq!(extract_field(&doc, "mime").unwrap(), "application/pdf");
        assert_eq!(
            extract_field(&doc, "media_type").unwrap(),
            "application/pdf"
        );
        assert_eq!(extract_field(&doc, "size").unwrap(), "12345");
        assert_eq!(extract_field(&doc, "byte_size").unwrap(), "12345");
        assert_eq!(extract_field(&doc, "alt").unwrap(), "passport scan");
        assert!(
            extract_field(&doc, "attachment")
                .unwrap()
                .starts_with("seren-secrets://attachment/")
        );
        assert!(
            extract_field(&doc, "uri")
                .unwrap()
                .starts_with("seren-secrets://attachment/")
        );
    }
}

//! 1Password `.1pux` archive importer.
//!
//! `.1pux` is the format 1Password 8 produces from "Export account data".
//! It is a ZIP archive containing plaintext JSON. Authenticating to the
//! 1Password app to perform the export is the access gate, so the importer
//! needs no password or Secret Key.
//!
//! Archive layout:
//!
//! - `export.data`: JSON with the full account contents (accounts > vaults
//!   > items).
//! - `export.attributes`: account metadata (not consumed here).
//! - `files/<documentId>/<filename>`: attachment payloads. The importer
//!   reads each entry, assigns it a fresh UUID, surfaces the bytes on
//!   [`ImportedItem::attachments`], and rewrites the referencing section
//!   field's value to a `seren-secrets://attachment/<uuid>` URI so the
//!   downstream client can resolve the bytes back to the inline reference
//!   at render time.
//!
//! ## What is mapped today
//!
//! - `001` Login -> `ItemContent::Login`
//! - `003` Secure Note -> `ItemContent::SecureNote`
//! - `005` Password -> `ItemContent::Login` with empty username
//! - `101` Bank Account -> `ItemContent::BankAccount`
//! - `102` Database -> `ItemContent::Database`
//! - `103` Driver License -> `ItemContent::DriverLicense`
//! - `106` Passport -> `ItemContent::Passport`
//! - `110` Server -> `ItemContent::Server`
//! - `112` API Credential -> `ItemContent::ApiCredential`
//! - `114` SSH Key -> `ItemContent::SshKey`
//! - `115` Crypto Wallet -> `ItemContent::CryptoWallet`
//! - everything else -> `ItemContent::ApiCredential` passthrough with source
//!   data preserved in `raw_import`
//!
//! Vault `name` becomes `ImportedItem::source_collection`; any non-zero
//! `favIndex` marks the item as favorite (1Password 8 typically writes a
//! unix timestamp here); `overview.tags` flows through to `tags`. Trashed or
//! archived items (`trashed == "Y"`, JSON `true`, or `state == "archived"`)
//! are dropped. Section fields are
//! flattened into `custom_fields` with `concealed` mapping to
//! `CustomFieldKind::Concealed`, and a TOTP `otpauth://` URI is promoted to
//! `TotpConfig` on a Login item.
//!
//! ## Verification status
//!
//! Round-trip tested against in-memory ZIP fixtures. NOT yet validated
//! against a real 1Password 8 export. Before relying on this in production
//! run a real export through and confirm the item shapes.

use crate::error::{CryptoError, CryptoResult};
use crate::import::otpauth::parse_otpauth_uri;
use crate::import::{
    ImportedAttachment, ImportedItem, custom_concealed_field, custom_string_field,
};
/// URI scheme that inline references to imported attachments use in
/// custom-field values. The destination client resolves the UUID against
/// `ImportedItem::attachments` to find the bytes. Kept identical to the
/// ProseMirror attachment scheme by re-exporting the shared constant.
pub use crate::prose::ATTACHMENT_URI_SCHEME;
use crate::protocol::item::{
    ApiCredentialContent, ApiCredentialKind, BankAccountContent, CardContent, CryptoWalletContent,
    CustomField, DatabaseContent, DocumentContent, DriverLicenseContent, GovernmentId,
    IdentityContent, ItemContent, LoginContent, LoginUrl, PassportContent, PasswordHistoryEntry,
    PostalAddress, Section as ImportedSection, SecureNoteContent, ServerContent, SshKeyContent,
    TotpConfig, WalletAddress,
};

use jiff::Timestamp;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use thiserror::Error;
use uuid::Uuid;
use zip::ZipArchive;

const EXPORT_DATA: &str = "export.data";

/// Hard cap on the decompressed size of `export.data`.
/// Real 1Password 8 exports for very large vaults sit comfortably under this.
const MAX_EXPORT_DATA_BYTES: u64 = 512 * 1024 * 1024;

/// Hard cap on the total decompressed size of attachment payloads. Each
/// individual attachment is also bounded by this. The cap is intentionally
/// the same as `MAX_EXPORT_DATA_BYTES` so a single decompression-bomb
/// budget governs the whole archive.
const MAX_ATTACHMENT_BYTES_TOTAL: u64 = 512 * 1024 * 1024;

/// Anything larger than this (per file) is rejected before its bytes are
/// pulled out of the archive, even if the total-cap budget would still
/// allow it.
const MAX_ATTACHMENT_BYTES_PER_FILE: u64 = 100 * 1024 * 1024;

/// Central-directory scan cap for pathological archives.
const MAX_ARCHIVE_ENTRIES: usize = 100_000;

#[derive(Debug, Error)]
pub enum OnePasswordImportError {
    #[error("not a zip archive")]
    NotZip,
    #[error("export.data missing from .1pux archive")]
    MissingExportData,
    #[error("read failed")]
    ReadFailure,
    #[error("export.data is not valid JSON")]
    InvalidJson,
    #[error("export.data exceeds the maximum allowed size")]
    ExportTooLarge,
    #[error("attachment payload exceeds the maximum allowed size")]
    AttachmentTooLarge,
    #[error("attachment path is malformed")]
    AttachmentPathMalformed,
    #[error("attachment documentId is duplicated in archive")]
    AttachmentDuplicateDocumentId,
    #[error("archive declares too many entries")]
    TooManyEntries,
}

impl From<OnePasswordImportError> for CryptoError {
    fn from(err: OnePasswordImportError) -> Self {
        match err {
            OnePasswordImportError::NotZip => CryptoError::Import("1pux is not a zip archive"),
            OnePasswordImportError::MissingExportData => {
                CryptoError::Import("1pux is missing export.data")
            }
            OnePasswordImportError::ReadFailure => CryptoError::Import("1pux read failed"),
            OnePasswordImportError::InvalidJson => CryptoError::Import("1pux json parse failed"),
            OnePasswordImportError::ExportTooLarge => {
                CryptoError::Import("1pux export.data is too large")
            }
            OnePasswordImportError::AttachmentTooLarge => {
                CryptoError::Import("1pux attachment payload is too large")
            }
            OnePasswordImportError::AttachmentPathMalformed => {
                CryptoError::Import("1pux attachment path is malformed")
            }
            OnePasswordImportError::AttachmentDuplicateDocumentId => {
                CryptoError::Import("1pux attachment documentId is duplicated")
            }
            OnePasswordImportError::TooManyEntries => {
                CryptoError::Import("1pux archive has too many entries")
            }
        }
    }
}

/// Decode a `.1pux` archive into a normalized item stream.
///
/// Runs entirely in-memory; nothing is written to disk and no network
/// traffic is generated. The decompressed size of `export.data` is capped
/// at the built-in archive size cap.
pub fn import_1pux(archive_bytes: &[u8]) -> CryptoResult<Vec<ImportedItem>> {
    import_1pux_with_cap(archive_bytes, MAX_EXPORT_DATA_BYTES)
}

/// Same as [`import_1pux`] but with an injectable decompressed-size cap.
/// Kept private so tests can exercise the bomb-rejection path without
/// allocating hundreds of megabytes of RAM.
fn import_1pux_with_cap(archive_bytes: &[u8], cap: u64) -> CryptoResult<Vec<ImportedItem>> {
    import_1pux_with_caps(
        archive_bytes,
        cap,
        MAX_ATTACHMENT_BYTES_PER_FILE,
        MAX_ATTACHMENT_BYTES_TOTAL,
    )
}

/// Inner entry point exposing the per-file and total attachment caps so
/// tests can exercise the bomb-rejection paths cheaply.
fn import_1pux_with_caps(
    archive_bytes: &[u8],
    export_cap: u64,
    attachment_per_file_cap: u64,
    attachment_total_cap: u64,
) -> CryptoResult<Vec<ImportedItem>> {
    let cursor = Cursor::new(archive_bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|_| OnePasswordImportError::NotZip)?;

    let mut buf = Vec::new();
    {
        let mut file = archive
            .by_name(EXPORT_DATA)
            .map_err(|_| OnePasswordImportError::MissingExportData)?;
        // Reject obvious bombs before allocating or decompressing anything.
        // The declared size in the central directory is untrusted but a
        // sanity check here lets us reject the worst cases cheaply.
        if file.size() > export_cap {
            return Err(OnePasswordImportError::ExportTooLarge.into());
        }
        // Decompress with a hard ceiling so a small archive that claims a
        // tiny uncompressed size but actually inflates past the cap still
        // gets stopped.
        let preallocate = file.size().min(export_cap) as usize;
        buf.reserve(preallocate);
        let mut limited = file.by_ref().take(export_cap + 1);
        limited
            .read_to_end(&mut buf)
            .map_err(|_| OnePasswordImportError::ReadFailure)?;
        if buf.len() as u64 > export_cap {
            return Err(OnePasswordImportError::ExportTooLarge.into());
        }
    }

    let export: Export =
        serde_json::from_slice(&buf).map_err(|_| OnePasswordImportError::InvalidJson)?;
    let attachment_pool =
        read_attachment_pool(&mut archive, attachment_per_file_cap, attachment_total_cap)?;
    Ok(export.into_items(&attachment_pool))
}

/// Read every `files/<documentId>/<filename>` entry into a map keyed by the
/// `documentId`. Each entry is bounded by `per_file_cap`; the sum of all
/// payloads is bounded by `total_cap`. Entries that do not match the
/// expected path shape are silently skipped (forward-compat with future
/// 1Password archive additions); malformed sizes are rejected.
///
/// Suspicious path components are rejected loudly rather than silently
/// massaged: any `doc_id` or `filename` containing `..`, `.`, embedded
/// path separators, leading/trailing whitespace, or NUL bytes trips
/// `AttachmentPathMalformed`. The importer never writes to disk, so this
/// is not a traversal defense. Duplicate documentIds across pool entries
/// fail loudly so the second entry cannot silently overwrite the
/// first while still draining the running budget.
fn read_attachment_pool(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    per_file_cap: u64,
    total_cap: u64,
) -> CryptoResult<HashMap<String, RawAttachment>> {
    let mut out: HashMap<String, RawAttachment> = HashMap::new();
    let mut budget: u64 = total_cap;
    let count = archive.len();
    if count > MAX_ARCHIVE_ENTRIES {
        return Err(OnePasswordImportError::TooManyEntries.into());
    }
    for i in 0..count {
        let mut file = archive
            .by_index(i)
            .map_err(|_| OnePasswordImportError::ReadFailure)?;
        let name = file.name().to_string();
        let Some(rest) = name.strip_prefix("files/") else {
            continue;
        };
        let Some((doc_id, filename)) = rest.split_once('/') else {
            // Directories and other shapes are skipped.
            continue;
        };
        if doc_id.is_empty() || filename.is_empty() {
            continue;
        }
        if !is_safe_path_component(doc_id) || !is_safe_path_component(filename) {
            return Err(OnePasswordImportError::AttachmentPathMalformed.into());
        }
        if out.contains_key(doc_id) {
            return Err(OnePasswordImportError::AttachmentDuplicateDocumentId.into());
        }
        if file.size() > per_file_cap {
            return Err(OnePasswordImportError::AttachmentTooLarge.into());
        }
        if file.size() > budget {
            return Err(OnePasswordImportError::AttachmentTooLarge.into());
        }
        let limit = per_file_cap.min(budget).saturating_add(1);
        let mut data = Vec::with_capacity(attachment_prealloc(file.size()));
        let mut limited = file.by_ref().take(limit);
        limited
            .read_to_end(&mut data)
            .map_err(|_| OnePasswordImportError::ReadFailure)?;
        if data.len() as u64 > per_file_cap || data.len() as u64 > budget {
            return Err(OnePasswordImportError::AttachmentTooLarge.into());
        }
        budget = budget.saturating_sub(data.len() as u64);
        out.insert(
            doc_id.to_string(),
            RawAttachment {
                filename: filename.to_string(),
                data,
            },
        );
    }
    Ok(out)
}

/// Cap initial capacity from declared ZIP metadata.
fn attachment_prealloc(declared_size: u64) -> usize {
    const ATTACHMENT_PREALLOC_CAP: u64 = 64 * 1024;
    declared_size.min(ATTACHMENT_PREALLOC_CAP) as usize
}

/// Reject path components that could confuse the pool key or downstream
/// filename rendering. The importer does not write to disk, so this is a
/// soundness check rather than a traversal defense.
fn is_safe_path_component(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    if s.trim() != s {
        return false;
    }
    !s.contains(['/', '\\', '\0'])
}

/// Raw attachment payload as it lives in the ZIP, before the importer
/// assigns a fresh UUID and surfaces it on `ImportedItem`.
struct RawAttachment {
    filename: String,
    data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// 1Password export JSON shapes
//
// Only the fields we actually consume are typed; everything else is
// captured into `raw` via `serde_json::Value` so the passthrough path can
// preserve unrecognized data losslessly.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Export {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Debug, Deserialize)]
struct Account {
    #[serde(default)]
    vaults: Vec<Vault>,
}

#[derive(Debug, Deserialize)]
struct Vault {
    #[serde(default)]
    attrs: VaultAttrs,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Debug, Default, Deserialize)]
struct VaultAttrs {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Item {
    // 1Password serializes favIndex as an integer; new builds use a unix
    // timestamp here, so a u64 leaves room past 2106.
    #[serde(default, rename = "favIndex")]
    fav_index: u64,
    // `trashed` is documented as the string "N" / "Y". Some builds and
    // adjacent tooling round-trip it as a JSON boolean, so accept both.
    #[serde(default)]
    trashed: serde_json::Value,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, rename = "categoryUuid")]
    category_uuid: Option<String>,
    #[serde(default)]
    overview: Overview,
    #[serde(default)]
    details: Details,
    #[serde(flatten)]
    raw: serde_json::Value,
}

/// Treat both `"Y"` and JSON `true` as trashed, and the documented
/// `state == "archived"` as out of scope for import.
fn is_trashed_or_archived(item: &Item) -> bool {
    if item
        .state
        .as_deref()
        .is_some_and(|state| state.eq_ignore_ascii_case("archived"))
    {
        return true;
    }
    match &item.trashed {
        serde_json::Value::String(s) => {
            s.eq_ignore_ascii_case("y") || s.eq_ignore_ascii_case("yes")
        }
        serde_json::Value::Bool(b) => *b,
        _ => false,
    }
}

#[derive(Debug, Default, Deserialize)]
struct Overview {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Vec<OverviewUrl>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OverviewUrl {
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Details {
    #[serde(default, rename = "loginFields")]
    login_fields: Vec<LoginField>,
    #[serde(default, rename = "notesPlain")]
    notes_plain: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    sections: Vec<Section>,
    // `.1pux` declares passwordHistory as `(PasswordHistoryEntity | null)[]
    // | null`, so the field can be absent, JSON null, or an array that
    // itself contains null members. A plain `Vec<PasswordHistory>` errors on
    // any null and would reject the entire export, so deserialize through a
    // helper that drops nulls instead of failing.
    #[serde(
        default,
        rename = "passwordHistory",
        deserialize_with = "de_password_history"
    )]
    password_history: Vec<PasswordHistory>,
}

#[derive(Debug, Deserialize)]
struct PasswordHistory {
    #[serde(default)]
    value: String,
    #[serde(default)]
    time: Option<i64>,
}

/// Accept absent / null / null-laden `passwordHistory` arrays without
/// rejecting the surrounding export. Null entries are dropped.
fn de_password_history<'de, D>(deserializer: D) -> Result<Vec<PasswordHistory>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<Vec<Option<PasswordHistory>>> = Option::deserialize(deserializer)?;
    Ok(raw.unwrap_or_default().into_iter().flatten().collect())
}

#[derive(Debug, Deserialize)]
struct LoginField {
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "fieldType")]
    field_type: Option<String>,
    #[serde(default)]
    designation: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Section {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    fields: Vec<SectionField>,
}

#[derive(Debug, Deserialize)]
struct SectionField {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    value: serde_json::Value,
}

impl Export {
    fn into_items(self, attachments: &HashMap<String, RawAttachment>) -> Vec<ImportedItem> {
        let mut out = Vec::new();
        for account in self.accounts {
            for vault in account.vaults {
                let collection = vault.attrs.name;
                for item in vault.items {
                    if is_trashed_or_archived(&item) {
                        continue;
                    }
                    out.push(build_item(item, collection.clone(), attachments));
                }
            }
        }
        out
    }
}

fn build_item(
    item: Item,
    collection: Option<String>,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let title = item
        .overview
        .title
        .clone()
        .unwrap_or_else(|| "Untitled".to_string());
    let favorite = item.fav_index != 0;
    let tags = item.overview.tags.clone();
    let category = item.category_uuid.clone().unwrap_or_default();

    // The category UUIDs through 114 are verified against the Bitwarden
    // 1pux importer types
    // (clients/libs/importer/src/importers/onepassword/types/
    //  onepassword-1pux-importer-types.ts). 115 is speculative: the
    // Bitwarden reference stops at 114 and the 1Password SDKs identify
    // categories by name rather than numeric UUID, so we have no
    // first-party fixture confirming CryptoWallet's .1pux code. A
    // wrongly-guessed 115 would misclassify some other category as
    // CryptoWallet, but every other category we map is verified, so the
    // worst case is one unknown category dropping into CryptoWallet
    // instead of the passthrough path. If a real .1pux export ever
    // shows otherwise, drop this arm and the passthrough branch picks
    // CryptoWallet up. The `build_crypto_wallet` function stays useful
    // either way - the dialog calls it directly when the user picks
    // Crypto wallet from the new-item kind rail.
    let mut imported = match category.as_str() {
        "001" => build_login(&item, attachments),
        "002" => build_card(&item, attachments),
        "003" => build_secure_note(&item, attachments),
        "004" => build_identity(&item, attachments),
        "005" => build_password(&item, attachments),
        "006" => build_document(&item, attachments),
        "101" => build_bank_account(&item, attachments),
        "102" => build_database(&item, attachments),
        "103" => build_driver_license(&item, attachments),
        "106" => build_passport(&item, attachments),
        "110" => build_server(&item, attachments),
        "112" => build_api_credential(&item, &category, attachments),
        "114" => build_ssh_key(&item, attachments),
        "115" => build_crypto_wallet(&item, attachments),
        _ => build_passthrough(&item, &category, attachments),
    };
    imported.title = title;
    imported.favorite = favorite;
    imported.tags = tags;
    imported.source_collection = collection;
    imported
}

fn item_notes(item: &Item) -> (crate::prose::ProseDoc, String) {
    crate::prose::from_plaintext(item.details.notes_plain.as_deref().unwrap_or(""))
}

fn build_login(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let (username, password) = login_credentials(&item.details.login_fields);
    let urls = collect_urls(&item.overview);
    let (custom_fields, totp, item_attachments) =
        section_fields_and_totp(&item.details.sections, attachments);
    let (notes, notes_text) = item_notes(item);

    let content = LoginContent {
        username,
        password,
        urls,
        totp,
        notes,
        notes_text,
        custom_fields,
        password_history: convert_password_history(&item.details.password_history),
        raw_import: serde_json::Value::Null,
        ..Default::default()
    };
    let mut imported = ImportedItem::new_login("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_secure_note(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let (custom_fields, _, item_attachments) =
        section_fields_and_totp(&item.details.sections, attachments);
    let (body, body_text) = item_notes(item);
    let content = SecureNoteContent {
        body,
        body_text,
        custom_fields,
        raw_import: onepassword_raw_import(item, "003"),
        ..Default::default()
    };
    let mut imported = ImportedItem::new_secure_note("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_password(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let urls = collect_urls(&item.overview);
    let (custom_fields, totp, item_attachments) =
        section_fields_and_totp(&item.details.sections, attachments);
    let (notes, notes_text) = item_notes(item);
    let content = LoginContent {
        username: String::new(),
        password: item.details.password.clone().unwrap_or_default(),
        urls,
        totp,
        notes,
        notes_text,
        custom_fields,
        password_history: convert_password_history(&item.details.password_history),
        raw_import: serde_json::Value::Null,
        ..Default::default()
    };
    let mut imported = ImportedItem::new_login("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_api_credential(
    item: &Item,
    category: &str,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let (mut custom_fields, _, item_attachments) =
        section_fields_and_totp(&item.details.sections, attachments);

    // 114 SSH Key surfaces (private, public) into (primary, secondary).
    // 112 API Credential surfaces (credential, username) the same way.
    let (primary, secondary) = if category == "114" {
        (
            extract_first(&mut custom_fields, &["private_key", "private key"]),
            extract_first(&mut custom_fields, &["public_key", "public key"]),
        )
    } else {
        (
            extract_first(&mut custom_fields, &["credential", "value"]),
            extract_first(&mut custom_fields, &["username"]),
        )
    };

    let (notes, notes_text) = item_notes(item);
    let content = ApiCredentialContent {
        kind: ApiCredentialKind::ApiKey,
        primary_value: primary,
        secondary_value: secondary,
        headers: std::collections::BTreeMap::new(),
        rotation: None,
        notes,
        notes_text,
        custom_fields,
        sections: Vec::new(),
        raw_import: onepassword_raw_import(item, category),
    };
    let mut imported = ImportedItem::new_api_credential("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_passthrough(
    item: &Item,
    category: &str,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let (custom_fields, _, item_attachments) =
        section_fields_and_totp(&item.details.sections, attachments);
    let (notes, notes_text) = item_notes(item);
    let content = ApiCredentialContent {
        kind: ApiCredentialKind::ApiKey,
        primary_value: String::new(),
        secondary_value: String::new(),
        headers: std::collections::BTreeMap::new(),
        rotation: None,
        notes,
        notes_text,
        custom_fields,
        sections: Vec::new(),
        raw_import: serde_json::json!({
            "onepassword_category": category,
            "source": item.raw.clone(),
        }),
    };
    let mut imported = ImportedItem::new_api_credential("", content);
    imported.attachments = item_attachments;
    imported
}

/// 1Password category 002 Credit Card.
///
/// Maps the well-known card fields by section-field title. Anything we do
/// not recognize (e.g. issuing bank, billing phone) falls through into
/// `custom_fields` via the existing classifier so nothing is lost.
fn build_card(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = CardContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    for section in &item.details.sections {
        for field in &section.fields {
            let title = field.title.clone().unwrap_or_default();
            let norm = normalize_field_title(&title);
            match norm.as_str() {
                "cardholdername" | "cardholder" | "nameoncard" => {
                    content.cardholder_name = scalar_value(&field.value);
                }
                "number" | "cardnumber" | "pan" => {
                    content.number = scalar_value(&field.value);
                }
                "type" | "brand" | "cardbrand" | "network" => {
                    content.brand = scalar_value(&field.value);
                }
                "expirydate" | "expirationdate" | "expiry" | "expiration" | "expires" => {
                    content.expiry = scalar_value(&field.value);
                }
                "verificationnumber" | "cvv" | "cvc" | "cvv2" | "securitycode" => {
                    content.cvv = scalar_value(&field.value);
                }
                "pin" => {
                    content.pin = scalar_value(&field.value);
                }
                _ => push_leftover(
                    &title,
                    &field.value,
                    attachments,
                    &mut item_attachments,
                    &mut leftover,
                ),
            }
        }
    }
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.custom_fields = leftover;
    content.raw_import = onepassword_raw_import(item, "002");
    let mut imported = ImportedItem::new_card("", content);
    imported.attachments = item_attachments;
    imported
}

/// 1Password category 004 Identity.
///
/// Walks sections matching the common name/address/contact field titles
/// and extracts a `PostalAddress` when an `address`-tagged value is found.
/// `government_ids` collects passport/license/SSN/national-id entries
/// keyed by their field title so an agent can resolve
/// `seren-secrets://v/i/passport_number` later.
fn build_identity(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = IdentityContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    for section in &item.details.sections {
        for field in &section.fields {
            let title = field.title.clone().unwrap_or_default();
            let norm = normalize_field_title(&title);
            match norm.as_str() {
                "firstname" | "givenname" => content.first_name = scalar_value(&field.value),
                "middlename" => content.middle_name = scalar_value(&field.value),
                "lastname" | "familyname" | "surname" => {
                    content.last_name = scalar_value(&field.value);
                }
                "email" | "emailaddress" => {
                    let v = scalar_value(&field.value);
                    if !v.is_empty() {
                        content.emails.push(crate::protocol::item::EmailEntry {
                            label: title.clone(),
                            value: v,
                        });
                    }
                }
                "phone" | "phonenumber" | "defaultphone" | "telephone" => {
                    let v = scalar_value(&field.value);
                    if !v.is_empty() {
                        content.phones.push(crate::protocol::item::PhoneEntry {
                            label: title.clone(),
                            value: v,
                        });
                    }
                }
                "username" => content.username = scalar_value(&field.value),
                "company" | "employer" => content.company = scalar_value(&field.value),
                "title" | "jobtitle" => content.job_title = scalar_value(&field.value),
                "sex" | "gender" => content.gender = scalar_value(&field.value),
                "birthdate" | "dateofbirth" | "dob" | "birthday" => {
                    let v = scalar_value(&field.value);
                    if !v.is_empty() {
                        content.date_of_birth = Some(v);
                    }
                }
                "address" | "homeaddress" | "mailingaddress" => {
                    if let Some(addr) = extract_postal_address(&field.value) {
                        content.addresses.push(addr);
                    }
                }
                "passport"
                | "passportnumber"
                | "drivinglicense"
                | "driverlicense"
                | "driverslicense"
                | "nationalid"
                | "socialsecuritynumber"
                | "ssn" => {
                    let number = scalar_value(&field.value);
                    if !number.is_empty() {
                        content.government_ids.push(GovernmentId {
                            label: title.clone(),
                            number,
                            issued_on: None,
                            expires_on: None,
                            issuer: String::new(),
                        });
                    }
                }
                _ => push_leftover(
                    &title,
                    &field.value,
                    attachments,
                    &mut item_attachments,
                    &mut leftover,
                ),
            }
        }
    }
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.custom_fields = leftover;
    content.raw_import = onepassword_raw_import(item, "004");
    let mut imported = ImportedItem::new_identity("", content);
    imported.attachments = item_attachments;
    imported
}

/// 1Password category 006 Document.
///
/// Documents are surfaced through `details.sections` with a `file`-tagged
/// section value referencing `files/<documentId>/<filename>` in the
/// archive. The first file value becomes the canonical
/// `attachment_uri`; anything else falls into `custom_fields` and the
/// remaining attachments still get ingested.
fn build_document(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = DocumentContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    let mut primary_assigned = false;
    for section in &item.details.sections {
        for field in &section.fields {
            let title = field.title.clone().unwrap_or_default();
            let mut taken_uri: Option<String> = None;
            let classified = classify_value(&field.value, attachments, &mut item_attachments);
            if matches!(classified, ClassifiedValue::String(_)) && !primary_assigned {
                // The classifier turned a `file` value into a
                // seren-secrets://attachment/ URI; the first such value
                // becomes the document's canonical attachment.
                if let ClassifiedValue::String(s) = &classified
                    && s.starts_with(crate::import::ATTACHMENT_URI_SCHEME)
                {
                    taken_uri = Some(s.clone());
                }
            }
            if let Some(uri) = taken_uri {
                primary_assigned = true;
                content.attachment_uri = uri;
                if let Some(filename) = item_attachments.last().map(|a| a.filename.clone()) {
                    content.filename = filename;
                }
                continue;
            }
            match classified {
                ClassifiedValue::String(s) => leftover.push(custom_string_field(title, s)),
                ClassifiedValue::Concealed(s) => leftover.push(custom_concealed_field(title, s)),
                ClassifiedValue::Totp(_) => { /* documents do not carry totp */ }
            }
        }
    }
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.custom_fields = leftover;
    content.raw_import = onepassword_raw_import(item, "006");
    let mut imported = ImportedItem::new_document("", content);
    imported.attachments = item_attachments;
    imported
}

/// 1Password category 114 SSH Key.
///
/// 1Password 8 stores the keypair under a section field whose value has
/// the `sshKey` tag with shape
/// `{ "sshKey": { "privateKey": "...", "metadata": { "publicKey": "...",
/// "fingerprint": "...", "keyType": "..." } } }`. We pluck those into
/// the typed fields; titles like "passphrase" and "key type" override on
/// the way through.
fn build_ssh_key(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = SshKeyContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    for section in &item.details.sections {
        for field in &section.fields {
            let title = field.title.clone().unwrap_or_default();
            let norm = normalize_field_title(&title);
            if let Some(inner) = extract_sshkey_value(&field.value) {
                if let Some(pk) = inner.get("privateKey").and_then(serde_json::Value::as_str) {
                    content.private_key = pk.to_string();
                }
                if let Some(meta) = inner.get("metadata") {
                    if let Some(pub_key) = meta.get("publicKey").and_then(serde_json::Value::as_str)
                    {
                        content.public_key = pub_key.to_string();
                    }
                    if let Some(fp) = meta.get("fingerprint").and_then(serde_json::Value::as_str) {
                        content.fingerprint = fp.to_string();
                    }
                    if let Some(kt) = meta.get("keyType").and_then(serde_json::Value::as_str) {
                        content.key_type = kt.to_string();
                    }
                }
                continue;
            }
            match norm.as_str() {
                "publickey" => content.public_key = scalar_value(&field.value),
                "privatekey" => content.private_key = scalar_value(&field.value),
                "fingerprint" => content.fingerprint = scalar_value(&field.value),
                "keytype" | "algorithm" => content.key_type = scalar_value(&field.value),
                "passphrase" => content.passphrase = scalar_value(&field.value),
                _ => push_leftover(
                    &title,
                    &field.value,
                    attachments,
                    &mut item_attachments,
                    &mut leftover,
                ),
            }
        }
    }
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.custom_fields = leftover;
    content.raw_import = onepassword_raw_import(item, "114");
    let mut imported = ImportedItem::new_ssh_key("", content);
    imported.attachments = item_attachments;
    imported
}

/// Canonicalize a section-field title for case- and punctuation-insensitive
/// matching: lowercased, with whitespace and ASCII punctuation stripped.
fn normalize_field_title(title: &str) -> String {
    title
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Read a section field value as a flat string regardless of tag.
/// Used by the typed importers when the field's tag is one of the
/// scalar shapes (string, concealed, creditCardNumber, monthYear,
/// creditCardType, phone, email, etc.).
fn scalar_value(value: &serde_json::Value) -> String {
    let serde_json::Value::Object(map) = value else {
        return value_to_string(value);
    };
    if let Some((_, inner)) = map.iter().next() {
        // The classifier-style tagged shapes wrap the scalar in a single
        // key/value pair; reach in once. Anything deeper (address, file,
        // sshKey) falls back to the JSON representation, but the typed
        // importers should not be calling this on those tags.
        return value_to_string(inner);
    }
    String::new()
}

/// Pull a `{ "address": { ... } }` section value into a `PostalAddress`,
/// translating 1Password's `state`/`zip` keys into our `region`/
/// `postal_code` names.
fn extract_postal_address(value: &serde_json::Value) -> Option<PostalAddress> {
    let inner = value.as_object()?.get("address")?.as_object()?;
    let take = |key: &str| -> String {
        inner
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let region = {
        let r = take("region");
        if r.is_empty() { take("state") } else { r }
    };
    let postal_code = {
        let p = take("postal_code");
        if p.is_empty() {
            let z = take("zip");
            if z.is_empty() { take("postcode") } else { z }
        } else {
            p
        }
    };
    let address = PostalAddress {
        street: take("street"),
        city: take("city"),
        region,
        postal_code,
        country: take("country"),
    };
    let is_empty = address.street.is_empty()
        && address.city.is_empty()
        && address.region.is_empty()
        && address.postal_code.is_empty()
        && address.country.is_empty();
    if is_empty { None } else { Some(address) }
}

/// Pull the inner object out of `{ "sshKey": { ... } }` if present.
fn extract_sshkey_value(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    value.as_object()?.get("sshKey")?.as_object()
}

/// Push an unrecognized section field into the leftover custom-field list,
/// routing through `classify_value` so file values still get ingested and
/// TOTP values get parsed (but skipped for the typed-item importers,
/// since identity/card/document/ssh items do not carry a TOTP slot).
fn push_leftover(
    title: &str,
    value: &serde_json::Value,
    attachments: &HashMap<String, RawAttachment>,
    item_attachments: &mut Vec<ImportedAttachment>,
    leftover: &mut Vec<CustomField>,
) {
    if title.is_empty() {
        return;
    }
    match classify_value(value, attachments, item_attachments) {
        ClassifiedValue::String(s) => leftover.push(custom_string_field(title.to_string(), s)),
        ClassifiedValue::Concealed(s) => {
            leftover.push(custom_concealed_field(title.to_string(), s));
        }
        ClassifiedValue::Totp(s) => {
            leftover.push(custom_concealed_field(title.to_string(), s));
        }
    }
}

/// Pull `(username, password)` from a Login item's `loginFields`. We prefer
/// the `designation` hint (1Password's own typed labels: `username` /
/// `password`) and fall back to a `name` of `"username"` / `"password"`.
///
/// `fieldType` is intentionally not used to classify a username: 1Password
/// uses single-letter HTML-style hints (`T` text, `E` email, `P` password,
/// `N` number, `A` textarea, `TEL` telephone), so `E` means "email", not
/// "username". A separate email field on a login form would otherwise get
/// promoted into the username slot. `fieldType == "P"` is still honored as
/// a password fallback because it is unambiguous in 1Password exports.
fn login_credentials(fields: &[LoginField]) -> (String, String) {
    let mut username = String::new();
    let mut password = String::new();
    for field in fields {
        let designation = field.designation.as_deref().unwrap_or("");
        let name = field.name.as_deref().unwrap_or("");
        let typ = field.field_type.as_deref().unwrap_or("");
        let value = field.value.clone().unwrap_or_default();

        let is_username =
            designation.eq_ignore_ascii_case("username") || name.eq_ignore_ascii_case("username");
        let is_password = designation.eq_ignore_ascii_case("password")
            || name.eq_ignore_ascii_case("password")
            || typ.eq_ignore_ascii_case("P");
        if is_username && username.is_empty() {
            username = value;
        } else if is_password && password.is_empty() {
            password = value;
        }
    }
    (username, password)
}

fn collect_urls(overview: &Overview) -> Vec<LoginUrl> {
    // 1Password 8 does not surface a per-URL match-type hint in the
    // export; the autofill behavior lives in a separate `autofillBehavior`
    // field that is not consistently populated. We carry the URLs through
    // with `match_type = None` so the destination client applies its own
    // default (host match in practice) rather than fabricate a hint.
    let mut urls: Vec<LoginUrl> = overview
        .urls
        .iter()
        .filter_map(|u| u.url.clone())
        .filter(|u| !u.is_empty())
        .map(LoginUrl::plain)
        .collect();
    if let Some(primary) = overview.url.as_ref()
        && !primary.is_empty()
        && !urls.iter().any(|u| &u.url == primary)
    {
        urls.insert(0, LoginUrl::plain(primary.clone()));
    }
    urls
}

/// Flatten section fields into a CustomField list. If a field's value is an
/// `otpauth://` TOTP URI, lift it out as a parsed `TotpConfig` so it can be
/// attached to a Login item rather than dropped into custom_fields as text.
///
/// File-typed section fields ingest the referenced bytes from
/// `attachments` (keyed by `documentId`), assign a fresh UUID, and emit a
/// `seren-secrets://attachment/<uuid>` URI in the custom field plus an
/// [`ImportedAttachment`] in the returned vector. A `file` value that
/// does not match any pooled attachment falls back to the filename so
/// the user can still locate the source manually.
fn section_fields_and_totp(
    sections: &[Section],
    attachments: &HashMap<String, RawAttachment>,
) -> (
    Vec<CustomField>,
    Option<TotpConfig>,
    Vec<ImportedAttachment>,
) {
    let mut fields = Vec::new();
    let mut totp = None;
    let mut item_attachments = Vec::new();
    for section in sections {
        for field in &section.fields {
            let name = field.title.clone().unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            match classify_value(&field.value, attachments, &mut item_attachments) {
                ClassifiedValue::String(s) => fields.push(custom_string_field(name, s)),
                ClassifiedValue::Concealed(s) => fields.push(custom_concealed_field(name, s)),
                ClassifiedValue::Totp(uri) => {
                    if totp.is_none()
                        && let Ok(parsed) = parse_otpauth_uri(&uri)
                        && let ItemContent::Login(login) = parsed.content
                    {
                        totp = login.totp;
                    } else {
                        fields.push(custom_concealed_field(name, uri));
                    }
                }
            }
        }
    }
    (fields, totp, item_attachments)
}

fn convert_password_history(history: &[PasswordHistory]) -> Vec<PasswordHistoryEntry> {
    let mut history: Vec<&PasswordHistory> = history
        .iter()
        .filter(|h| !h.value.is_empty() && h.time.is_some())
        .collect();
    history.sort_by_key(|h| std::cmp::Reverse(h.time.unwrap_or_default()));
    history
        .into_iter()
        .map(|h| PasswordHistoryEntry {
            password: h.value.clone(),
            changed_at: format_1password_history_time(h.time.unwrap_or_default()),
        })
        .collect()
}

fn format_1password_history_time(time: i64) -> String {
    let parsed = if time >= 10_000_000_000 || time <= -10_000_000_000 {
        Timestamp::from_millisecond(time)
    } else {
        Timestamp::from_second(time)
    };
    parsed
        .map(|ts| ts.to_string())
        .unwrap_or_else(|_| time.to_string())
}

fn onepassword_raw_import(item: &Item, category: &str) -> serde_json::Value {
    if item.details.password_history.is_empty() {
        return serde_json::json!({ "onepassword_category": category });
    }
    let history: Vec<serde_json::Value> = item
        .details
        .password_history
        .iter()
        .filter(|h| !h.value.is_empty() || h.time.is_some())
        .map(|h| {
            serde_json::json!({
                "value": &h.value,
                "time": h.time,
            })
        })
        .collect();
    if history.is_empty() {
        return serde_json::json!({ "onepassword_category": category });
    }
    serde_json::json!({
        "onepassword_category": category,
        "password_history": history,
    })
}

enum ClassifiedValue {
    String(String),
    Concealed(String),
    Totp(String),
}

/// Turn a section field's `value` (the tagged-union 1Password serializes)
/// into a flat string with a kind hint.
///
/// `address` and `file` carry a nested object rather than a scalar, so they
/// are flattened to a human-readable string rather than emitted as raw
/// JSON. The full structured shape is still preserved on passthrough items
/// through `Item::raw`. Unknown scalar tags fall back to a JSON-stringified
/// `String` so nothing silently disappears.
///
/// `file` values look up their `documentId` in the archive's attachment
/// pool. Matches produce both a `seren-secrets://attachment/<uuid>` URI
/// (returned through the classifier) and a populated
/// [`ImportedAttachment`] in `item_attachments`. Misses fall back to the
/// filename string so the user can still find the bytes manually.
fn classify_value(
    value: &serde_json::Value,
    attachments: &HashMap<String, RawAttachment>,
    item_attachments: &mut Vec<ImportedAttachment>,
) -> ClassifiedValue {
    let serde_json::Value::Object(map) = value else {
        return ClassifiedValue::String(value_to_string(value));
    };
    if let Some((tag, inner)) = map.iter().next() {
        match tag.as_str() {
            "string" | "url" | "email" | "phone" | "date" | "monthYear" | "gender" | "menu"
            | "reference" | "creditCardNumber" | "creditCardType" => {
                ClassifiedValue::String(value_to_string(inner))
            }
            "concealed" => ClassifiedValue::Concealed(value_to_string(inner)),
            "totp" => ClassifiedValue::Totp(value_to_string(inner)),
            "address" => ClassifiedValue::String(format_address(inner)),
            "file" => {
                ClassifiedValue::String(ingest_file_value(inner, attachments, item_attachments))
            }
            _ => ClassifiedValue::String(value_to_string(value)),
        }
    } else {
        ClassifiedValue::String(String::new())
    }
}

/// Resolve a `file` section value against the archive's attachment pool.
/// When the pool has bytes for the referenced `documentId`, mint a fresh
/// UUID, emit an [`ImportedAttachment`], and return the
/// `seren-secrets://attachment/<uuid>` URI so the custom field's value
/// becomes a stable reference. When the pool has nothing for the id, fall
/// back to the filename so the user can still locate the source.
fn ingest_file_value(
    inner: &serde_json::Value,
    attachments: &HashMap<String, RawAttachment>,
    item_attachments: &mut Vec<ImportedAttachment>,
) -> String {
    let serde_json::Value::Object(map) = inner else {
        return value_to_string(inner);
    };
    let document_id = map
        .get("documentId")
        .and_then(|v| v.as_str())
        .or_else(|| map.get("id").and_then(|v| v.as_str()));

    if let Some(doc_id) = document_id
        && let Some(raw) = attachments.get(doc_id)
    {
        let new_id = Uuid::new_v4();
        let declared_filename = map
            .get("fileName")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map_or_else(|| raw.filename.clone(), str::to_string);
        item_attachments.push(ImportedAttachment {
            id: new_id,
            filename: declared_filename,
            content_type: None,
            data: raw.data.clone(),
        });
        return format!("{ATTACHMENT_URI_SCHEME}{new_id}");
    }

    format_file_reference(inner)
}

fn value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Render an `address` section value as a single human-readable line.
/// Falls back to a JSON representation when the shape is unexpected so no
/// structural information is dropped silently.
fn format_address(inner: &serde_json::Value) -> String {
    let serde_json::Value::Object(map) = inner else {
        return value_to_string(inner);
    };
    // 1Password serializes addresses as a flat object with keys like
    // street, city, region, country, zip. Join the populated parts in a
    // stable visual order rather than relying on map iteration order.
    let parts = ["street", "city", "region", "zip", "state", "country"];
    let mut rendered: Vec<String> = parts
        .iter()
        .filter_map(|k| map.get(*k).and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if rendered.is_empty() {
        // Fall back to any remaining string fields so the value is never
        // silently empty when 1Password ships an unexpected key set.
        rendered = map
            .values()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
    }
    if rendered.is_empty() {
        inner.to_string()
    } else {
        rendered.join(", ")
    }
}

/// Fallback rendering for a `file` section value when the archive does not
/// carry matching bytes under `files/<documentId>/<filename>` (or the
/// caller is parsing JSON without the surrounding ZIP). Returns the
/// filename so the user can still locate the attachment manually.
fn format_file_reference(inner: &serde_json::Value) -> String {
    let serde_json::Value::Object(map) = inner else {
        return value_to_string(inner);
    };
    for key in ["fileName", "filename", "name", "documentId", "id"] {
        if let Some(v) = map.get(key).and_then(|v| v.as_str())
            && !v.is_empty()
        {
            return v.to_string();
        }
    }
    inner.to_string()
}

/// Remove the first custom field whose name matches any candidate
/// (case-insensitive, spaces and underscores equivalent) and return its
/// value. Used to lift well-known API-credential fields up into
/// `primary_value` / `secondary_value`.
fn extract_first(fields: &mut Vec<CustomField>, candidates: &[&str]) -> String {
    let normalized: Vec<String> = candidates
        .iter()
        .map(|c| c.to_ascii_lowercase().replace(' ', "_"))
        .collect();
    if let Some(pos) = fields.iter().position(|f| {
        let name = f.name.to_ascii_lowercase().replace(' ', "_");
        normalized.iter().any(|c| c == &name)
    }) {
        fields.remove(pos).value
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// New 1Password categories: bank account, passport, driver licence, server,
// database, crypto wallet. These walk the same section/field structure used
// for Identity / Card and pluck known field titles into the typed slots on
// the matching content struct. Unmapped fields land in `custom_fields` so
// nothing is lost; the source section ids carry over verbatim so the UI can
// render the layout the user already knows.
// ---------------------------------------------------------------------------

fn import_sections(item: &Item) -> Vec<ImportedSection> {
    item.details
        .sections
        .iter()
        .filter_map(|s| {
            let title = s.title.clone().unwrap_or_default();
            // 1pux gives us section titles but no stable id. Use the title
            // as the id so a field's section_id keeps pointing at the
            // same section across edits; if the user later renames a
            // section in our UI, the id becomes detached from the title
            // (which is the desired behavior).
            if title.is_empty() {
                None
            } else {
                Some(ImportedSection {
                    id: title.clone(),
                    title,
                })
            }
        })
        .collect()
}

/// Walk every section/field on the item and yield (section_id_or_empty,
/// normalized_title, original_title, value). Lets the per-kind importers
/// extract their typed slots without re-implementing the section walk.
fn for_each_field(item: &Item, mut visit: impl FnMut(&str, String, String, &serde_json::Value)) {
    for section in &item.details.sections {
        let section_id = section.title.as_deref().unwrap_or("");
        for field in &section.fields {
            let title = field.title.clone().unwrap_or_default();
            let norm = normalize_field_title(&title);
            visit(section_id, norm, title, &field.value);
        }
    }
}

fn build_bank_account(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = BankAccountContent::default();
    let mut leftover: Vec<CustomField> = Vec::new();
    let mut item_attachments: Vec<ImportedAttachment> = Vec::new();
    for_each_field(item, |section_id, norm, title, value| {
        let v = scalar_value(value);
        match norm.as_str() {
            "bankname" => content.bank_name = v,
            "owner" | "accountholder" | "nameonaccount" => content.account_holder = v,
            "accountnumber" | "accountno" => content.account_number = v,
            "routingnumber" | "routing" | "aba" => content.routing_number = v,
            "accounttype" | "type" => content.account_type = v,
            "iban" => content.iban = v,
            "swift" | "swiftcode" | "bic" => content.swift = v,
            "branchaddress" | "branch" => content.branch = v,
            "pin" | "pinnumber" | "telephonepin" => content.pin = v,
            _ if !v.is_empty() => leftover.push(CustomField {
                name: title.to_string(),
                kind: crate::protocol::item::CustomFieldKind::String,
                value: v,
                purpose: None,
                section_id: section_id_or_none(section_id),
            }),
            _ => {}
        }
        absorb_attachments_for(value, attachments, &mut item_attachments);
    });
    content.custom_fields = leftover;
    content.sections = import_sections(item);
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.raw_import = onepassword_raw_import(item, "101");
    let mut imported = ImportedItem::new_bank_account("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_passport(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = PassportContent::default();
    let mut leftover: Vec<CustomField> = Vec::new();
    let mut item_attachments: Vec<ImportedAttachment> = Vec::new();
    for_each_field(item, |section_id, norm, title, value| {
        let v = scalar_value(value);
        match norm.as_str() {
            "number" | "passportnumber" => content.number = v,
            "type" | "passporttype" => content.passport_type = v,
            "fullname" | "name" => content.full_name = v,
            "surname" | "familyname" | "lastname" => content.surname = v,
            "givennames" | "firstname" | "givenname" => content.given_names = v,
            "nationality" | "country" => content.nationality = v,
            "dateofbirth" | "birthdate" | "dob" | "birthday" if !v.is_empty() => {
                content.date_of_birth = Some(v)
            }
            "placeofbirth" | "birthplace" => content.place_of_birth = v,
            "sex" | "gender" => content.gender = v,
            "issuingcountry" => content.issuing_country = v,
            "issuingauthority" | "authority" => content.issuing_authority = v,
            "issued" | "issuedon" | "issuedate" | "dateissued" if !v.is_empty() => {
                content.issued_on = Some(v)
            }
            "expires" | "expireson" | "expiry" | "expirationdate" | "dateofexpiry"
                if !v.is_empty() =>
            {
                content.expires_on = Some(v)
            }
            _ if !v.is_empty() => leftover.push(CustomField {
                name: title.to_string(),
                kind: crate::protocol::item::CustomFieldKind::String,
                value: v,
                purpose: None,
                section_id: section_id_or_none(section_id),
            }),
            _ => {}
        }
        absorb_attachments_for(value, attachments, &mut item_attachments);
    });
    content.custom_fields = leftover;
    content.sections = import_sections(item);
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.raw_import = onepassword_raw_import(item, "106");
    let mut imported = ImportedItem::new_passport("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_driver_license(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = DriverLicenseContent::default();
    let mut leftover: Vec<CustomField> = Vec::new();
    let mut item_attachments: Vec<ImportedAttachment> = Vec::new();
    for_each_field(item, |section_id, norm, title, value| {
        let v = scalar_value(value);
        match norm.as_str() {
            "number" | "licensenumber" | "drivinglicense" | "driverlicense" => {
                content.number = v;
            }
            "fullname" | "name" => content.full_name = v,
            "dateofbirth" | "birthdate" | "dob" | "birthday" if !v.is_empty() => {
                content.date_of_birth = Some(v)
            }
            "sex" | "gender" => content.gender = v,
            "address" | "homeaddress" => {
                if let Some(addr) = extract_postal_address(value) {
                    content.address = Some(addr);
                }
            }
            "country" => content.country = v,
            "state" | "province" => content.state = v,
            "class" | "licenseclass" => content.license_class = v,
            "conditions" | "restrictions" | "conditionsrestrictions" | "endorsements" => {
                content.conditions = v
            }
            "issued" | "issuedon" | "dateissued" if !v.is_empty() => content.issued_on = Some(v),
            "expires" | "expireson" | "expiry" | "expirationdate" if !v.is_empty() => {
                content.expires_on = Some(v)
            }
            _ if !v.is_empty() => leftover.push(CustomField {
                name: title.to_string(),
                kind: crate::protocol::item::CustomFieldKind::String,
                value: v,
                purpose: None,
                section_id: section_id_or_none(section_id),
            }),
            _ => {}
        }
        absorb_attachments_for(value, attachments, &mut item_attachments);
    });
    content.custom_fields = leftover;
    content.sections = import_sections(item);
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.raw_import = onepassword_raw_import(item, "103");
    let mut imported = ImportedItem::new_driver_license("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_crypto_wallet(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = CryptoWalletContent::default();
    let mut leftover: Vec<CustomField> = Vec::new();
    let mut item_attachments: Vec<ImportedAttachment> = Vec::new();
    for_each_field(item, |section_id, norm, title, value| {
        let v = scalar_value(value);
        let kind = match norm.as_str() {
            "name" | "walletname" => {
                content.wallet_name = v;
                None
            }
            "network" | "chain" => {
                content.network = v;
                None
            }
            "recoveryphrase" | "seedphrase" | "mnemonic" | "seed" => {
                content.seed_phrase = v;
                None
            }
            "privatekey" | "secretkey" => {
                content.private_key = v;
                None
            }
            "password" | "passphrase" => {
                content.password = v;
                None
            }
            "derivationpath" | "path" => {
                content.derivation_path = v;
                None
            }
            // Any field whose normalized title ends in "address" gets
            // promoted into the wallet's address list with the original
            // title as the label. Crypto wallets routinely label
            // multiple addresses ("Receiving address", "Cold storage
            // address", ...), so an exact match would only ever catch
            // the first.
            _ if norm.ends_with("address") => {
                if !v.is_empty() {
                    content.addresses.push(WalletAddress {
                        label: title.to_string(),
                        address: v,
                    });
                }
                None
            }
            _ => Some(v),
        };
        if let Some(remaining) = kind
            && !remaining.is_empty()
        {
            leftover.push(CustomField {
                name: title.to_string(),
                kind: crate::protocol::item::CustomFieldKind::String,
                value: remaining,
                purpose: None,
                section_id: section_id_or_none(section_id),
            });
        }
        absorb_attachments_for(value, attachments, &mut item_attachments);
    });
    content.custom_fields = leftover;
    content.sections = import_sections(item);
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.raw_import = onepassword_raw_import(item, "115");
    let mut imported = ImportedItem::new_crypto_wallet("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_server(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = ServerContent::default();
    let mut leftover: Vec<CustomField> = Vec::new();
    let mut item_attachments: Vec<ImportedAttachment> = Vec::new();
    for_each_field(item, |section_id, norm, title, value| {
        let v = scalar_value(value);
        match norm.as_str() {
            "url" | "hostname" | "host" | "server" => content.hostname = v,
            "port" => {
                if let Ok(parsed) = v.parse::<u32>() {
                    content.port = Some(parsed);
                }
            }
            "protocol" | "scheme" => content.protocol = v,
            "username" | "user" | "loginname" => content.username = v,
            "password" => content.password = v,
            "sshkey" | "sshkeyreference" => content.ssh_key_reference = v,
            "adminconsoleurl" | "adminurl" | "console" => content.admin_console_url = v,
            _ if !v.is_empty() => leftover.push(CustomField {
                name: title.to_string(),
                kind: crate::protocol::item::CustomFieldKind::String,
                value: v,
                purpose: None,
                section_id: section_id_or_none(section_id),
            }),
            _ => {}
        }
        absorb_attachments_for(value, attachments, &mut item_attachments);
    });
    content.custom_fields = leftover;
    content.sections = import_sections(item);
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.raw_import = onepassword_raw_import(item, "110");
    let mut imported = ImportedItem::new_server("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_database(item: &Item, attachments: &HashMap<String, RawAttachment>) -> ImportedItem {
    let mut content = DatabaseContent::default();
    let mut leftover: Vec<CustomField> = Vec::new();
    let mut item_attachments: Vec<ImportedAttachment> = Vec::new();
    for_each_field(item, |section_id, norm, title, value| {
        let v = scalar_value(value);
        match norm.as_str() {
            "type" | "databasetype" | "engine" => content.database_type = v,
            "server" | "host" | "hostname" => content.server = v,
            "port" => {
                if let Ok(parsed) = v.parse::<u32>() {
                    content.port = Some(parsed);
                }
            }
            "database" | "databasename" => content.database_name = v,
            "username" | "user" | "loginname" => content.username = v,
            "password" => content.password = v,
            "sid" => content.sid = v,
            "schema" => content.schema = v,
            _ if !v.is_empty() => leftover.push(CustomField {
                name: title.to_string(),
                kind: crate::protocol::item::CustomFieldKind::String,
                value: v,
                purpose: None,
                section_id: section_id_or_none(section_id),
            }),
            _ => {}
        }
        absorb_attachments_for(value, attachments, &mut item_attachments);
    });
    content.custom_fields = leftover;
    content.sections = import_sections(item);
    let (notes, notes_text) = item_notes(item);
    content.notes = notes;
    content.notes_text = notes_text;
    content.raw_import = onepassword_raw_import(item, "102");
    let mut imported = ImportedItem::new_database("", content);
    imported.attachments = item_attachments;
    imported
}

fn section_id_or_none(section_id: &str) -> Option<String> {
    if section_id.is_empty() {
        None
    } else {
        Some(section_id.to_string())
    }
}

/// If `value` references an attachment by UUID, pull the corresponding
/// `RawAttachment` out of the per-archive index and append it to
/// `out`. No-op when the value isn't an attachment reference or the
/// archive doesn't carry the matching bytes. Used by the new build_*
/// functions so each typed kind preserves attached files the same way
/// `build_login` / `build_card` / etc. already do.
fn absorb_attachments_for(
    value: &serde_json::Value,
    attachments: &HashMap<String, RawAttachment>,
    out: &mut Vec<ImportedAttachment>,
) {
    let attachment_id = match value {
        serde_json::Value::Object(map) => map
            .get("attachmentUUID")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        _ => None,
    };
    if let Some(id) = attachment_id
        && let Some(raw) = attachments.get(&id)
    {
        out.push(ImportedAttachment {
            id: uuid::Uuid::new_v4(),
            filename: raw.filename.clone(),
            content_type: None,
            data: raw.data.clone(),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::CustomFieldKind;

    use std::io::Write;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    /// Build a minimal `.1pux` archive containing only `export.data`.
    fn build_archive(export_json: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file(EXPORT_DATA, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(export_json.as_bytes()).unwrap();
            writer.finish().unwrap();
        }
        buf
    }

    fn single_item_payload(
        category: &str,
        overview: serde_json::Value,
        details: serde_json::Value,
    ) -> String {
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Personal" },
                    "items": [{
                        "uuid": "abc",
                        "favIndex": 1,
                        "trashed": "N",
                        "categoryUuid": category,
                        "overview": overview,
                        "details": details,
                    }]
                }]
            }]
        });
        serde_json::to_string(&export).unwrap()
    }

    #[test]
    fn rejects_non_zip_input() {
        let err = import_1pux(b"not a zip").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_zip_without_export_data() {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file("other.json", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"{}").unwrap();
            writer.finish().unwrap();
        }
        let err = import_1pux(&buf).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn imports_a_login_with_totp_and_custom_fields() {
        let overview = serde_json::json!({
            "title": "GitHub",
            "url": "https://github.com",
            "urls": [{ "url": "https://github.com" }],
            "tags": ["dev", "primary"],
        });
        let details = serde_json::json!({
            "loginFields": [
                { "designation": "username", "value": "alice", "fieldType": "T", "name": "username" },
                { "designation": "password", "value": "hunter2", "fieldType": "P", "name": "password" }
            ],
            "notesPlain": "ssh key backup",
            "sections": [{
                "title": "Extra",
                "fields": [
                    { "title": "API token", "value": { "concealed": "sk_live_x" } },
                    { "title": "one-time password", "value": { "totp": "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub" } },
                    { "title": "homepage", "value": { "url": "https://github.com/alice" } }
                ]
            }],
            "passwordHistory": [
                { "value": "oldest-password", "time": 1635522854 },
                { "value": "newest-password", "time": 1635522872 }
            ]
        });
        let payload = build_archive(&single_item_payload("001", overview, details));

        let items = import_1pux(&payload).unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.title, "GitHub");
        assert!(item.favorite);
        assert_eq!(item.tags, vec!["dev", "primary"]);
        assert_eq!(item.source_collection.as_deref(), Some("Personal"));
        match &item.content {
            ItemContent::Login(login) => {
                assert_eq!(login.username, "alice");
                assert_eq!(login.password, "hunter2");
                assert_eq!(login.urls.len(), 1);
                assert_eq!(login.urls[0].url, "https://github.com");
                assert!(login.urls[0].match_type.is_none());
                assert_eq!(login.notes_text, "ssh key backup");
                let totp = login.totp.as_ref().expect("totp lifted from section");
                assert_eq!(totp.secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(login.custom_fields.len(), 2);
                let api = login
                    .custom_fields
                    .iter()
                    .find(|f| f.name == "API token")
                    .unwrap();
                assert_eq!(api.kind, CustomFieldKind::Concealed);
                assert_eq!(api.value, "sk_live_x");
                let homepage = login
                    .custom_fields
                    .iter()
                    .find(|f| f.name == "homepage")
                    .unwrap();
                assert_eq!(homepage.kind, CustomFieldKind::String);
                assert_eq!(homepage.value, "https://github.com/alice");
                assert_eq!(login.password_history.len(), 2);
                assert_eq!(login.password_history[0].password, "newest-password");
                assert_eq!(login.password_history[0].changed_at, "2021-10-29T15:54:32Z");
                assert_eq!(login.password_history[1].password, "oldest-password");
                assert_eq!(login.password_history[1].changed_at, "2021-10-29T15:54:14Z");
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn null_password_history_does_not_reject_export() {
        // `.1pux` exports legitimately emit `"passwordHistory": null`; that
        // must yield an empty history, not reject the whole export.
        let overview = serde_json::json!({ "title": "GitHub" });
        let details = serde_json::json!({
            "loginFields": [
                { "designation": "password", "value": "hunter2", "fieldType": "P", "name": "password" }
            ],
            "passwordHistory": serde_json::Value::Null,
        });
        let payload = build_archive(&single_item_payload("001", overview, details));
        let items = import_1pux(&payload).expect("null passwordHistory must not reject export");
        assert_eq!(items.len(), 1);
        match &items[0].content {
            ItemContent::Login(login) => assert!(login.password_history.is_empty()),
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn null_history_element_is_dropped_not_rejected() {
        // The array element type is `PasswordHistoryEntity | null`, so a null
        // member must be skipped rather than failing the export.
        let overview = serde_json::json!({ "title": "GitHub" });
        let details = serde_json::json!({
            "loginFields": [
                { "designation": "password", "value": "hunter2", "fieldType": "P", "name": "password" }
            ],
            "passwordHistory": [
                serde_json::Value::Null,
                { "value": "old", "time": 1635522854 }
            ],
        });
        let payload = build_archive(&single_item_payload("001", overview, details));
        let items = import_1pux(&payload).expect("null history element must not reject export");
        match &items[0].content {
            ItemContent::Login(login) => {
                assert_eq!(login.password_history.len(), 1);
                assert_eq!(login.password_history[0].password, "old");
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn normalizes_punctuation_in_field_titles() {
        assert_eq!(
            normalize_field_title("conditions / restrictions"),
            "conditionsrestrictions"
        );
        assert_eq!(normalize_field_title("account #"), "account");
    }

    #[test]
    fn imports_a_secure_note() {
        let overview = serde_json::json!({ "title": "Wifi" });
        let details = serde_json::json!({
            "notesPlain": "ssid: home\npass: secret",
            "sections": [{
                "fields": [{ "title": "Network", "value": { "string": "home" } }]
            }],
            "passwordHistory": [
                { "value": "old wifi pass", "time": 1635522872000_i64 }
            ]
        });
        let payload = build_archive(&single_item_payload("003", overview, details));

        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::SecureNote(note) => {
                assert_eq!(note.body_text, "ssid: home\npass: secret");
                assert_eq!(note.custom_fields.len(), 1);
                assert_eq!(note.custom_fields[0].name, "Network");
                assert_eq!(note.custom_fields[0].value, "home");
                assert_eq!(note.raw_import["onepassword_category"], "003");
                assert_eq!(
                    note.raw_import["password_history"][0]["value"],
                    "old wifi pass"
                );
                assert_eq!(
                    note.raw_import["password_history"][0]["time"],
                    1635522872000_i64
                );
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn imports_a_password_only_item_as_login_with_empty_username() {
        let overview = serde_json::json!({ "title": "Recovery code" });
        let details = serde_json::json!({
            "password": "abcd-1234",
        });
        let payload = build_archive(&single_item_payload("005", overview, details));

        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Login(login) => {
                assert_eq!(login.username, "");
                assert_eq!(login.password, "abcd-1234");
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn imports_api_credential_with_credential_extracted() {
        let overview = serde_json::json!({ "title": "Stripe" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "credential", "value": { "concealed": "sk_test_x" } },
                    { "title": "username", "value": { "string": "stripe_admin" } },
                    { "title": "endpoint", "value": { "url": "https://api.stripe.com" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("112", overview, details));

        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::ApiCredential(api) => {
                assert_eq!(api.primary_value, "sk_test_x");
                assert_eq!(api.secondary_value, "stripe_admin");
                assert_eq!(api.custom_fields.len(), 1);
                assert_eq!(api.custom_fields[0].name, "endpoint");
                assert_eq!(api.raw_import["onepassword_category"], "112");
            }
            _ => panic!("expected ApiCredential"),
        }
    }

    #[test]
    fn passes_unknown_category_through_with_raw_import() {
        let overview = serde_json::json!({ "title": "License" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{ "title": "key", "value": { "string": "XYZ-123" } }]
            }]
        });
        // 100 = Software License (not specialized today).
        let payload = build_archive(&single_item_payload("100", overview, details));

        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::ApiCredential(api) => {
                assert_eq!(api.raw_import["onepassword_category"], "100");
                assert!(api.raw_import["source"].is_object(), "raw source preserved");
                assert_eq!(api.custom_fields.len(), 1);
                assert_eq!(api.custom_fields[0].name, "key");
            }
            _ => panic!("expected passthrough ApiCredential"),
        }
    }

    #[test]
    fn drops_trashed_items() {
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Personal" },
                    "items": [
                        {
                            "categoryUuid": "001",
                            "trashed": "Y",
                            "overview": { "title": "Stale" },
                            "details": {}
                        },
                        {
                            "categoryUuid": "001",
                            "trashed": "N",
                            "overview": { "title": "Live" },
                            "details": {}
                        }
                    ]
                }]
            }]
        });
        let payload = build_archive(&export.to_string());
        let items = import_1pux(&payload).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Live");
    }

    #[test]
    fn vault_name_becomes_source_collection_and_missing_title_falls_back() {
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Work" },
                    "items": [{
                        "categoryUuid": "001",
                        "details": {},
                        "overview": {}
                    }]
                }]
            }]
        });
        let payload = build_archive(&export.to_string());
        let items = import_1pux(&payload).unwrap();
        assert_eq!(items[0].title, "Untitled");
        assert_eq!(items[0].source_collection.as_deref(), Some("Work"));
    }

    #[test]
    fn email_fieldtype_does_not_become_username() {
        // 1Password's `fieldType: "E"` means "email", not "username". When a
        // login form has both an email field and a username field with no
        // designation, the email value must not be promoted into the
        // username slot.
        let overview = serde_json::json!({ "title": "Site" });
        let details = serde_json::json!({
            "loginFields": [
                { "value": "alice@example.com", "fieldType": "E", "name": "email" },
                { "designation": "password", "value": "pw", "fieldType": "P", "name": "password" }
            ]
        });
        let payload = build_archive(&single_item_payload("001", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Login(login) => {
                assert_eq!(login.username, "", "email must not be promoted to username");
                assert_eq!(login.password, "pw");
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn favindex_accepts_timestamp_value() {
        // 1Password 8 stores favIndex as a unix timestamp, which overflows
        // a u32. Make sure deserialization still works and that any
        // non-zero value is interpreted as favorite.
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Personal" },
                    "items": [{
                        "categoryUuid": "001",
                        "favIndex": 1_700_000_000_u64,
                        "overview": { "title": "Pinned" },
                        "details": {}
                    }]
                }]
            }]
        });
        let payload = build_archive(&export.to_string());
        let items = import_1pux(&payload).unwrap();
        assert!(items[0].favorite);
    }

    #[test]
    fn trashed_boolean_is_treated_as_trashed() {
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Personal" },
                    "items": [
                        {
                            "categoryUuid": "001",
                            "trashed": true,
                            "overview": { "title": "Stale" },
                            "details": {}
                        },
                        {
                            "categoryUuid": "001",
                            "trashed": false,
                            "overview": { "title": "Live" },
                            "details": {}
                        }
                    ]
                }]
            }]
        });
        let payload = build_archive(&export.to_string());
        let items = import_1pux(&payload).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Live");
    }

    #[test]
    fn archived_state_is_dropped() {
        let export = serde_json::json!({
            "accounts": [{
                "vaults": [{
                    "attrs": { "name": "Personal" },
                    "items": [
                        {
                            "categoryUuid": "001",
                            "state": "archived",
                            "overview": { "title": "Archived" },
                            "details": {}
                        },
                        {
                            "categoryUuid": "001",
                            "state": "active",
                            "overview": { "title": "Live" },
                            "details": {}
                        }
                    ]
                }]
            }]
        });
        let payload = build_archive(&export.to_string());
        let items = import_1pux(&payload).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Live");
    }

    #[test]
    fn nested_address_is_flattened_to_readable_line() {
        let overview = serde_json::json!({ "title": "Home" });
        let details = serde_json::json!({
            "sections": [{
                "title": "Address",
                "fields": [{
                    "title": "primary",
                    "value": { "address": {
                        "street": "1 Infinite Loop",
                        "city": "Cupertino",
                        "region": "CA",
                        "zip": "95014",
                        "country": "us"
                    } }
                }]
            }]
        });
        let payload = build_archive(&single_item_payload("003", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::SecureNote(note) => {
                assert_eq!(note.custom_fields.len(), 1);
                assert_eq!(note.custom_fields[0].name, "primary");
                let v = &note.custom_fields[0].value;
                assert!(v.contains("1 Infinite Loop"), "got {v}");
                assert!(v.contains("Cupertino"), "got {v}");
                assert!(v.contains("95014"), "got {v}");
                assert!(!v.contains('{'), "address must not be raw JSON: {v}");
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn file_value_keeps_filename_rather_than_raw_json() {
        let overview = serde_json::json!({ "title": "Doc" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "attachment",
                    "value": { "file": { "fileName": "passport.pdf", "documentId": "xyz" } }
                }]
            }]
        });
        let payload = build_archive(&single_item_payload("003", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::SecureNote(note) => {
                assert_eq!(note.custom_fields[0].value, "passport.pdf");
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn export_data_size_cap_constant_matches_512mib() {
        // Sanity guard: if anyone tightens the cap below typical real
        // exports, this test will trip and force a deliberate decision.
        assert_eq!(MAX_EXPORT_DATA_BYTES, 512 * 1024 * 1024);
    }

    #[test]
    fn attachment_prealloc_is_capped_against_declared_size() {
        const CAP: usize = 64 * 1024;
        assert_eq!(attachment_prealloc(10), 10);
        assert_eq!(attachment_prealloc(CAP as u64), CAP);
        assert_eq!(attachment_prealloc(100 * 1024 * 1024), CAP);
        assert_eq!(attachment_prealloc(u64::MAX), CAP);
    }

    #[test]
    fn rejects_decompression_bomb() {
        // A tiny zip whose deflate stream inflates well past the cap must
        // be rejected before the decompressed payload exceeds the cap.
        // We use a small injected cap so the test stays fast in CI.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            writer.start_file(EXPORT_DATA, options).unwrap();
            // Zeros compress to a tiny deflate stream, so the archive
            // stays in the kilobyte range even though the uncompressed
            // payload is several MiB.
            let chunk = vec![0u8; 64 * 1024];
            for _ in 0..64 {
                writer.write_all(&chunk).unwrap();
            }
            writer.finish().unwrap();
        }
        let err = import_1pux_with_cap(&buf, 1024).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_oversize_declared_export_data() {
        // A stored (uncompressed) archive whose declared size is over the
        // cap must be rejected before any bytes are read out.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer.start_file(EXPORT_DATA, options).unwrap();
            // 2KiB payload, cap 1KiB.
            writer.write_all(&vec![b'a'; 2048]).unwrap();
            writer.finish().unwrap();
        }
        let err = import_1pux_with_cap(&buf, 1024).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    /// Build an archive containing `export.data` plus one
    /// `files/<documentId>/<filename>` entry with `bytes`. Used by the
    /// attachment-ingestion tests below.
    fn build_archive_with_file(
        export_json: &str,
        document_id: &str,
        filename: &str,
        bytes: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file(EXPORT_DATA, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(export_json.as_bytes()).unwrap();
            writer
                .start_file(
                    format!("files/{document_id}/{filename}"),
                    SimpleFileOptions::default(),
                )
                .unwrap();
            writer.write_all(bytes).unwrap();
            writer.finish().unwrap();
        }
        buf
    }

    #[test]
    fn file_value_with_pooled_bytes_becomes_attachment_with_uri_reference() {
        // A section field whose value carries a `file` tag with a
        // `documentId` that resolves to bytes in `files/<id>/<name>` must
        // surface those bytes as an `ImportedAttachment` and rewrite the
        // custom-field value to a `seren-secrets://attachment/<uuid>` URI
        // so the downstream client can resolve the bytes back to the
        // reference at render time.
        let document_id = "doc-1234";
        let attachment_bytes = b"hello attachment".to_vec();
        let overview = serde_json::json!({ "title": "Recovery codes" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "Backup",
                    "value": {
                        "file": {
                            "fileName": "recovery.txt",
                            "documentId": document_id,
                            "size": attachment_bytes.len(),
                        }
                    }
                }]
            }]
        });
        let payload = build_archive_with_file(
            &single_item_payload("003", overview, details),
            document_id,
            "recovery.txt",
            &attachment_bytes,
        );

        let items = import_1pux(&payload).unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.attachments.len(), 1);
        let attachment = &item.attachments[0];
        assert_eq!(attachment.filename, "recovery.txt");
        assert_eq!(attachment.data, attachment_bytes);
        // Fresh UUID, not the source documentId.
        assert_ne!(attachment.id.to_string(), document_id);

        match &item.content {
            ItemContent::SecureNote(n) => {
                assert_eq!(n.custom_fields.len(), 1);
                assert_eq!(n.custom_fields[0].name, "Backup");
                assert_eq!(
                    n.custom_fields[0].value,
                    format!("{ATTACHMENT_URI_SCHEME}{}", attachment.id)
                );
                assert_eq!(n.custom_fields[0].kind, CustomFieldKind::String);
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn file_value_without_pooled_bytes_falls_back_to_filename() {
        // The same file-shaped section field, but the archive has no
        // matching `files/<id>/...` entry. The importer must not panic or
        // synthesize an attachment; instead it keeps the filename as the
        // custom-field value so the user can still find the source.
        let overview = serde_json::json!({ "title": "Missing attachment" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "Backup",
                    "value": {
                        "file": {
                            "fileName": "missing.bin",
                            "documentId": "doc-not-in-archive"
                        }
                    }
                }]
            }]
        });
        // build_archive (no files entry) leaves the attachment pool empty.
        let payload = build_archive(&single_item_payload("003", overview, details));
        let items = import_1pux(&payload).unwrap();
        let item = &items[0];
        assert!(item.attachments.is_empty());
        match &item.content {
            ItemContent::SecureNote(n) => {
                assert_eq!(n.custom_fields[0].value, "missing.bin");
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn rejects_attachment_over_per_file_cap() {
        // A single file larger than the per-file cap is refused before
        // the bytes are pulled out of the archive.
        let document_id = "doc-big";
        let overview = serde_json::json!({ "title": "Big attachment" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "Backup",
                    "value": { "file": { "documentId": document_id, "fileName": "big.bin" } }
                }]
            }]
        });
        let payload = build_archive_with_file(
            &single_item_payload("003", overview, details),
            document_id,
            "big.bin",
            &vec![b'a'; 4096],
        );
        let err = import_1pux_with_caps(
            &payload,
            /*export_cap=*/ 1024 * 1024,
            /*per_file=*/ 1024,
            /*total=*/ 1024 * 1024,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_attachment_total_over_combined_cap() {
        // Two attachments individually under the per-file cap together
        // exceed the total cap; the second one trips the budget check.
        let overview = serde_json::json!({ "title": "Two attachments" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "A", "value": { "file": { "documentId": "doc-a", "fileName": "a.bin" } } },
                    { "title": "B", "value": { "file": { "documentId": "doc-b", "fileName": "b.bin" } } }
                ]
            }]
        });
        // Two 800-byte files; per-file cap 1024, total cap 1024.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file(EXPORT_DATA, SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(single_item_payload("003", overview, details).as_bytes())
                .unwrap();
            writer
                .start_file("files/doc-a/a.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&vec![b'a'; 800]).unwrap();
            writer
                .start_file("files/doc-b/b.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&vec![b'b'; 800]).unwrap();
            writer.finish().unwrap();
        }
        let err = import_1pux_with_caps(
            &buf,
            /*export_cap=*/ 1024 * 1024,
            /*per_file=*/ 1024,
            /*total=*/ 1024,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn zero_byte_attachment_is_ingested() {
        // A legitimate 0-byte attachment (empty file in the archive) must
        // be surfaced as an ImportedAttachment with an empty data vec, not
        // dropped or treated as a missing-pool fallback.
        let document_id = "doc-empty";
        let overview = serde_json::json!({ "title": "Empty doc" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "Empty",
                    "value": { "file": { "documentId": document_id, "fileName": "empty.bin" } }
                }]
            }]
        });
        let payload = build_archive_with_file(
            &single_item_payload("003", overview, details),
            document_id,
            "empty.bin",
            &[],
        );
        let items = import_1pux(&payload).unwrap();
        let item = &items[0];
        assert_eq!(item.attachments.len(), 1);
        assert!(item.attachments[0].data.is_empty());
        match &item.content {
            ItemContent::SecureNote(n) => {
                assert!(n.custom_fields[0].value.starts_with(ATTACHMENT_URI_SCHEME));
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn duplicate_document_id_in_pool_is_rejected() {
        // Two archive entries claiming the same documentId would let the
        // second silently overwrite the first while still draining the
        // running budget. Fail loudly instead.
        let overview = serde_json::json!({ "title": "Dup" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "X",
                    "value": { "file": { "documentId": "doc-x", "fileName": "x.bin" } }
                }]
            }]
        });
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file(EXPORT_DATA, SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(single_item_payload("003", overview, details).as_bytes())
                .unwrap();
            writer
                .start_file("files/doc-x/first.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"first").unwrap();
            writer
                .start_file("files/doc-x/second.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"second").unwrap();
            writer.finish().unwrap();
        }
        let err = import_1pux(&buf).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn suspicious_path_component_is_rejected() {
        // `files/../export.data` would strip the prefix and split to
        // `doc_id = ".."`, `filename = "export.data"`. The importer never
        // writes to disk, but these names would create confusing pool keys.
        // Reject loudly.
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file(EXPORT_DATA, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"{}").unwrap();
            writer
                .start_file("files/../sneaky.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"bytes").unwrap();
            writer.finish().unwrap();
        }
        let err = import_1pux(&buf).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn multiple_sections_referencing_same_document_id_each_get_unique_uuids() {
        // Two section fields pointing at the same documentId currently
        // each receive a fresh UUID and a clone of the bytes. The fields'
        // URIs must differ so a downstream renderer can tell them apart;
        // the attachments themselves carry the same payload.
        let document_id = "doc-shared";
        let bytes = b"shared payload".to_vec();
        let overview = serde_json::json!({ "title": "Shared" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "First",  "value": { "file": { "documentId": document_id, "fileName": "shared.bin" } } },
                    { "title": "Second", "value": { "file": { "documentId": document_id, "fileName": "shared.bin" } } }
                ]
            }]
        });
        let payload = build_archive_with_file(
            &single_item_payload("003", overview, details),
            document_id,
            "shared.bin",
            &bytes,
        );
        let items = import_1pux(&payload).unwrap();
        let item = &items[0];
        assert_eq!(item.attachments.len(), 2);
        assert_ne!(item.attachments[0].id, item.attachments[1].id);
        assert_eq!(item.attachments[0].data, bytes);
        assert_eq!(item.attachments[1].data, bytes);
        match &item.content {
            ItemContent::SecureNote(n) => {
                assert_eq!(n.custom_fields.len(), 2);
                assert_ne!(n.custom_fields[0].value, n.custom_fields[1].value);
                assert!(n.custom_fields[0].value.starts_with(ATTACHMENT_URI_SCHEME));
                assert!(n.custom_fields[1].value.starts_with(ATTACHMENT_URI_SCHEME));
            }
            _ => panic!("expected SecureNote"),
        }
    }

    #[test]
    fn second_attachment_exactly_fills_remaining_budget() {
        // Boundary case for the running-budget arithmetic: after the
        // first attachment consumes part of the budget, the second
        // attachment whose size equals the remaining budget exactly must
        // be accepted (not off-by-one rejected).
        let overview = serde_json::json!({ "title": "Tight fit" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "A", "value": { "file": { "documentId": "doc-a", "fileName": "a.bin" } } },
                    { "title": "B", "value": { "file": { "documentId": "doc-b", "fileName": "b.bin" } } }
                ]
            }]
        });
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut writer = ZipWriter::new(cursor);
            writer
                .start_file(EXPORT_DATA, SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(single_item_payload("003", overview, details).as_bytes())
                .unwrap();
            writer
                .start_file("files/doc-a/a.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&vec![b'a'; 512]).unwrap();
            writer
                .start_file("files/doc-b/b.bin", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&vec![b'b'; 512]).unwrap();
            writer.finish().unwrap();
        }
        let items = import_1pux_with_caps(
            &buf,
            /*export_cap=*/ 1024 * 1024,
            /*per_file=*/ 1024,
            /*total=*/ 1024,
        )
        .unwrap();
        assert_eq!(items[0].attachments.len(), 2);
    }

    #[test]
    fn attachment_keeps_pool_filename_when_section_omits_one() {
        // Some 1Password 8 builds store the filename only inside the
        // archive entry path; the section field carries only a
        // documentId. The importer must fall back to the pool's filename
        // rather than producing an empty string.
        let document_id = "doc-noname";
        let bytes = b"payload".to_vec();
        let overview = serde_json::json!({ "title": "Filename-from-pool" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "Doc",
                    "value": { "file": { "documentId": document_id } }
                }]
            }]
        });
        let payload = build_archive_with_file(
            &single_item_payload("003", overview, details),
            document_id,
            "from-pool.bin",
            &bytes,
        );
        let items = import_1pux(&payload).unwrap();
        let item = &items[0];
        assert_eq!(item.attachments.len(), 1);
        assert_eq!(item.attachments[0].filename, "from-pool.bin");
    }

    #[test]
    fn category_002_maps_to_card_with_brand_and_cvv() {
        let overview = serde_json::json!({ "title": "Visa Personal" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "Cardholder Name", "value": { "string": "Alice Example" } },
                    { "title": "type", "value": { "creditCardType": "visa" } },
                    { "title": "number", "value": { "creditCardNumber": "4242424242424242" } },
                    { "title": "expiry date", "value": { "monthYear": "05/2030" } },
                    { "title": "verification number", "value": { "concealed": "123" } },
                    { "title": "PIN", "value": { "concealed": "0000" } },
                    { "title": "issuing bank", "value": { "string": "Test Bank" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("002", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Card(card) => {
                assert_eq!(card.cardholder_name, "Alice Example");
                assert_eq!(card.brand, "visa");
                assert_eq!(card.number, "4242424242424242");
                assert_eq!(card.expiry, "05/2030");
                assert_eq!(card.cvv, "123");
                assert_eq!(card.pin, "0000");
                // Unknown title falls into custom_fields verbatim.
                assert_eq!(card.custom_fields.len(), 1);
                assert_eq!(card.custom_fields[0].name, "issuing bank");
            }
            other => panic!("expected Card, got {other:?}"),
        }
    }

    #[test]
    fn category_004_maps_to_identity_with_postal_address() {
        let overview = serde_json::json!({ "title": "Personal" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "first name", "value": { "string": "Alice" } },
                    { "title": "last name", "value": { "string": "Example" } },
                    { "title": "email", "value": { "string": "alice@example.com" } },
                    { "title": "default phone", "value": { "phone": "+1-555-0100" } },
                    { "title": "address", "value": { "address": {
                        "street": "1 Test Way",
                        "city": "Springfield",
                        "state": "IL",
                        "zip": "62701",
                        "country": "USA"
                    }}},
                    { "title": "passport number", "value": { "string": "P00000000" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("004", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Identity(id) => {
                assert_eq!(id.first_name, "Alice");
                assert_eq!(id.last_name, "Example");
                assert_eq!(id.emails[0].value, "alice@example.com");
                assert_eq!(id.phones[0].value, "+1-555-0100");
                let addr = id.addresses.first().expect("address mapped");
                assert_eq!(addr.street, "1 Test Way");
                assert_eq!(addr.region, "IL");
                assert_eq!(addr.postal_code, "62701");
                assert_eq!(id.government_ids.len(), 1);
                assert_eq!(id.government_ids[0].number, "P00000000");
            }
            other => panic!("expected Identity, got {other:?}"),
        }
    }

    #[test]
    fn category_103_maps_slash_joined_conditions_title() {
        let overview = serde_json::json!({ "title": "License" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "number", "value": { "string": "D1234567" } },
                    { "title": "conditions / restrictions", "value": { "string": "Corrective lenses" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("103", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::DriverLicense(license) => {
                assert_eq!(license.number, "D1234567");
                assert_eq!(license.conditions, "Corrective lenses");
            }
            other => panic!("expected DriverLicense, got {other:?}"),
        }
    }

    #[test]
    fn category_114_maps_to_ssh_key_from_typed_value() {
        let overview = serde_json::json!({ "title": "Deploy key" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "private key", "value": { "sshKey": {
                        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA",
                        "metadata": {
                            "publicKey": "ssh-ed25519 AAAA deploy",
                            "fingerprint": "SHA256:abc",
                            "keyType": "ed25519"
                        }
                    }}},
                    { "title": "passphrase", "value": { "concealed": "p4ss" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("114", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::SshKey(k) => {
                assert!(k.private_key.starts_with("-----BEGIN OPENSSH"));
                assert_eq!(k.public_key, "ssh-ed25519 AAAA deploy");
                assert_eq!(k.fingerprint, "SHA256:abc");
                assert_eq!(k.key_type, "ed25519");
                assert_eq!(k.passphrase, "p4ss");
            }
            other => panic!("expected SshKey, got {other:?}"),
        }
    }

    #[test]
    fn category_006_maps_to_document_with_attachment_uri() {
        let document_id = "doc-001";
        let overview = serde_json::json!({ "title": "Resume" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "document",
                    "value": { "file": {
                        "documentId": document_id,
                        "fileName": "resume.pdf"
                    }}
                }]
            }]
        });
        let payload = build_archive_with_file(
            &single_item_payload("006", overview, details),
            document_id,
            "resume.pdf",
            b"PDF-bytes",
        );
        let items = import_1pux(&payload).unwrap();
        let item = &items[0];
        assert_eq!(item.attachments.len(), 1);
        match &item.content {
            ItemContent::Document(doc) => {
                assert_eq!(doc.filename, "resume.pdf");
                let expected_prefix = crate::import::ATTACHMENT_URI_SCHEME;
                assert!(doc.attachment_uri.starts_with(expected_prefix));
                // The URI's UUID matches the surfaced attachment id.
                let uuid_str = doc.attachment_uri.trim_start_matches(expected_prefix);
                assert_eq!(uuid_str, item.attachments[0].id.to_string());
            }
            other => panic!("expected Document, got {other:?}"),
        }
    }

    #[test]
    fn category_006_with_missing_file_pool_leaves_attachment_uri_empty() {
        // Document categories whose `file` section value points at a
        // documentId not present in the archive must not panic and must
        // not synthesize a seren-secrets:// URI. The filename string
        // falls back into custom_fields so the user can locate the
        // source manually, and the typed slots stay empty.
        let overview = serde_json::json!({ "title": "Resume" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [{
                    "title": "document",
                    "value": { "file": {
                        "documentId": "doc-not-in-archive",
                        "fileName": "resume.pdf"
                    }}
                }]
            }]
        });
        let payload = build_archive(&single_item_payload("006", overview, details));
        let items = import_1pux(&payload).unwrap();
        let item = &items[0];
        assert!(item.attachments.is_empty());
        match &item.content {
            ItemContent::Document(doc) => {
                assert_eq!(doc.attachment_uri, "");
                assert_eq!(doc.filename, "");
                // The filename string still flows through into
                // custom_fields under the section title.
                assert_eq!(doc.custom_fields.len(), 1);
                assert_eq!(doc.custom_fields[0].name, "document");
                assert_eq!(doc.custom_fields[0].value, "resume.pdf");
            }
            other => panic!("expected Document, got {other:?}"),
        }
    }

    #[test]
    fn category_006_with_no_file_sections_produces_empty_document() {
        // A Document item that carries no file-tagged section fields at
        // all (e.g. notes-only document) must still produce a Document
        // item with an empty attachment_uri rather than falling through
        // to a typed-mismatch panic.
        let overview = serde_json::json!({ "title": "Notes only" });
        let details = serde_json::json!({
            "notesPlain": "draft body",
            "sections": [{
                "fields": [
                    { "title": "summary", "value": { "string": "draft" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("006", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Document(doc) => {
                assert_eq!(doc.attachment_uri, "");
                assert_eq!(doc.filename, "");
                assert_eq!(doc.notes_text, "draft body");
                assert_eq!(doc.custom_fields.len(), 1);
                assert_eq!(doc.custom_fields[0].name, "summary");
            }
            other => panic!("expected Document, got {other:?}"),
        }
    }

    #[test]
    fn category_002_with_empty_card_section_still_maps_to_card() {
        // A 1Password card item whose sections carry none of the known
        // card field titles must still produce a CardContent (with all
        // slots empty) so the typed dispatch is the single source of
        // truth. Unknown section fields land in custom_fields.
        let overview = serde_json::json!({ "title": "Empty card" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "issuing bank", "value": { "string": "Test Bank" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("002", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Card(card) => {
                assert_eq!(card.cardholder_name, "");
                assert_eq!(card.number, "");
                assert_eq!(card.brand, "");
                assert_eq!(card.expiry, "");
                assert_eq!(card.cvv, "");
                assert_eq!(card.custom_fields.len(), 1);
                assert_eq!(card.custom_fields[0].name, "issuing bank");
            }
            other => panic!("expected Card, got {other:?}"),
        }
    }

    #[test]
    fn category_004_with_null_address_value_leaves_address_none() {
        // 1Password section fields can ship `value: null` when the user
        // cleared an address. The importer must not crash, and `address`
        // must stay None rather than Some(empty PostalAddress).
        let overview = serde_json::json!({ "title": "No address" });
        let details = serde_json::json!({
            "sections": [{
                "fields": [
                    { "title": "first name", "value": { "string": "Alice" } },
                    { "title": "address", "value": null }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("004", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Identity(id) => {
                assert_eq!(id.first_name, "Alice");
                assert!(id.addresses.is_empty());
            }
            other => panic!("expected Identity, got {other:?}"),
        }
    }

    #[test]
    fn imports_a_bank_account_with_typed_fields_and_sections() {
        let overview = serde_json::json!({ "title": "Checking" });
        let details = serde_json::json!({
            "sections": [
                {
                    "title": "Account",
                    "fields": [
                        { "title": "bank name", "value": { "string": "Acme Bank" } },
                        { "title": "owner", "value": { "string": "Alice Example" } },
                        { "title": "account number", "value": { "string": "0123456789" } },
                        { "title": "routing number", "value": { "string": "021000021" } },
                        { "title": "type", "value": { "menu": "checking" } },
                        { "title": "IBAN", "value": { "string": "GB29 NWBK 6016 1331 9268 19" } },
                        { "title": "SWIFT", "value": { "string": "NWBKGB2L" } }
                    ]
                },
                {
                    "title": "Security",
                    "fields": [
                        { "title": "PIN", "value": { "concealed": "1234" } },
                        { "title": "branch address", "value": { "string": "1 High Street" } },
                        { "title": "notes only known to me", "value": { "string": "vault under the desk" } }
                    ]
                }
            ]
        });
        let payload = build_archive(&single_item_payload("101", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::BankAccount(bank) => {
                assert_eq!(bank.bank_name, "Acme Bank");
                assert_eq!(bank.account_holder, "Alice Example");
                assert_eq!(bank.account_number, "0123456789");
                assert_eq!(bank.routing_number, "021000021");
                assert_eq!(bank.account_type, "checking");
                assert_eq!(bank.iban, "GB29 NWBK 6016 1331 9268 19");
                assert_eq!(bank.swift, "NWBKGB2L");
                assert_eq!(bank.pin, "1234");
                assert_eq!(bank.branch, "1 High Street");
                // Unmapped field lands in custom_fields tagged with section.
                let leftover = bank
                    .custom_fields
                    .iter()
                    .find(|f| f.name == "notes only known to me")
                    .expect("unmapped field preserved");
                assert_eq!(leftover.section_id.as_deref(), Some("Security"));
                // Sections list reflects the source titles.
                let section_titles: Vec<&str> =
                    bank.sections.iter().map(|s| s.title.as_str()).collect();
                assert!(section_titles.contains(&"Account"));
                assert!(section_titles.contains(&"Security"));
            }
            other => panic!("expected BankAccount, got {other:?}"),
        }
    }

    #[test]
    fn imports_a_passport_with_typed_fields() {
        let overview = serde_json::json!({ "title": "US Passport" });
        let details = serde_json::json!({
            "sections": [{
                "title": "Passport",
                "fields": [
                    { "title": "number", "value": { "string": "P00000000" } },
                    { "title": "full name", "value": { "string": "Alice Example" } },
                    { "title": "nationality", "value": { "string": "USA" } },
                    { "title": "date of birth", "value": { "date": "1990-04-12" } },
                    { "title": "place of birth", "value": { "string": "Springfield, IL" } },
                    { "title": "sex", "value": { "string": "F" } },
                    { "title": "issuing country", "value": { "string": "USA" } },
                    { "title": "issuing authority", "value": { "string": "US Dept of State" } },
                    { "title": "issued on", "value": { "date": "2020-01-01" } },
                    { "title": "expires", "value": { "date": "2030-01-01" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("106", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Passport(p) => {
                assert_eq!(p.number, "P00000000");
                assert_eq!(p.full_name, "Alice Example");
                assert_eq!(p.nationality, "USA");
                assert_eq!(p.date_of_birth.as_deref(), Some("1990-04-12"));
                assert_eq!(p.place_of_birth, "Springfield, IL");
                assert_eq!(p.gender, "F");
                assert_eq!(p.issuing_country, "USA");
                assert_eq!(p.issuing_authority, "US Dept of State");
                assert_eq!(p.issued_on.as_deref(), Some("2020-01-01"));
                assert_eq!(p.expires_on.as_deref(), Some("2030-01-01"));
            }
            other => panic!("expected Passport, got {other:?}"),
        }
    }

    #[test]
    fn imports_a_driver_license_with_address_and_conditions() {
        let overview = serde_json::json!({ "title": "CA Driver Licence" });
        let details = serde_json::json!({
            "sections": [{
                "title": "Driver licence",
                "fields": [
                    { "title": "number", "value": { "string": "D1234567" } },
                    { "title": "full name", "value": { "string": "Alice Example" } },
                    { "title": "date of birth", "value": { "date": "1990-04-12" } },
                    { "title": "sex", "value": { "string": "F" } },
                    { "title": "country", "value": { "string": "USA" } },
                    { "title": "state", "value": { "string": "CA" } },
                    { "title": "class", "value": { "string": "C" } },
                    { "title": "conditions / restrictions", "value": { "string": "Corrective lenses" } },
                    { "title": "expires", "value": { "date": "2030-04-12" } },
                    { "title": "address", "value": { "address": {
                        "street": "1 Test Way",
                        "city": "Springfield",
                        "region": "IL",
                        "zip": "62701",
                        "country": "USA"
                    } } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("103", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::DriverLicense(l) => {
                assert_eq!(l.number, "D1234567");
                assert_eq!(l.full_name, "Alice Example");
                assert_eq!(l.date_of_birth.as_deref(), Some("1990-04-12"));
                assert_eq!(l.gender, "F");
                assert_eq!(l.country, "USA");
                assert_eq!(l.state, "CA");
                assert_eq!(l.license_class, "C");
                // Slash + spaces in source title still map to typed slot.
                assert_eq!(l.conditions, "Corrective lenses");
                assert_eq!(l.expires_on.as_deref(), Some("2030-04-12"));
                let addr = l.address.as_ref().expect("license address parsed");
                assert_eq!(addr.street, "1 Test Way");
                assert_eq!(addr.region, "IL");
                assert_eq!(addr.postal_code, "62701");
            }
            other => panic!("expected DriverLicense, got {other:?}"),
        }
    }

    #[test]
    fn imports_a_crypto_wallet_with_seed_and_multiple_addresses() {
        let overview = serde_json::json!({ "title": "Hot wallet" });
        let details = serde_json::json!({
            "sections": [{
                "title": "Wallet",
                "fields": [
                    { "title": "wallet name", "value": { "string": "Daily" } },
                    { "title": "network", "value": { "string": "Ethereum" } },
                    { "title": "recovery phrase", "value": { "concealed": "abandon ability able about above absent absorb abstract absurd abuse access accident" } },
                    { "title": "private key", "value": { "concealed": "0xdeadbeef" } },
                    { "title": "password", "value": { "concealed": "wallet-pass" } },
                    { "title": "derivation path", "value": { "string": "m/44'/60'/0'/0/0" } },
                    { "title": "Receiving address", "value": { "string": "0xAAAA" } },
                    { "title": "Cold storage address", "value": { "string": "0xBBBB" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("115", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::CryptoWallet(w) => {
                assert_eq!(w.wallet_name, "Daily");
                assert_eq!(w.network, "Ethereum");
                assert!(w.seed_phrase.starts_with("abandon ability"));
                assert_eq!(w.private_key, "0xdeadbeef");
                assert_eq!(w.password, "wallet-pass");
                assert_eq!(w.derivation_path, "m/44'/60'/0'/0/0");
                assert_eq!(w.addresses.len(), 2);
                let labels: Vec<&str> = w.addresses.iter().map(|a| a.label.as_str()).collect();
                assert!(labels.contains(&"Receiving address"));
                assert!(labels.contains(&"Cold storage address"));
                let values: Vec<&str> = w.addresses.iter().map(|a| a.address.as_str()).collect();
                assert!(values.contains(&"0xAAAA"));
                assert!(values.contains(&"0xBBBB"));
            }
            other => panic!("expected CryptoWallet, got {other:?}"),
        }
    }

    #[test]
    fn imports_a_server_with_credentials_and_ssh_key_reference() {
        let overview = serde_json::json!({ "title": "deploy-prod" });
        let details = serde_json::json!({
            "sections": [{
                "title": "Server",
                "fields": [
                    { "title": "URL", "value": { "url": "ssh://deploy@10.0.0.1" } },
                    { "title": "port", "value": { "string": "22" } },
                    { "title": "protocol", "value": { "string": "ssh" } },
                    { "title": "username", "value": { "string": "deploy" } },
                    { "title": "password", "value": { "concealed": "rotate-me" } },
                    { "title": "SSH key", "value": { "string": "seren-secrets://v/i/private_key" } },
                    { "title": "admin console URL", "value": { "url": "https://10.0.0.1/admin" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("110", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Server(s) => {
                assert_eq!(s.hostname, "ssh://deploy@10.0.0.1");
                assert_eq!(s.port, Some(22));
                assert_eq!(s.protocol, "ssh");
                assert_eq!(s.username, "deploy");
                assert_eq!(s.password, "rotate-me");
                assert_eq!(s.ssh_key_reference, "seren-secrets://v/i/private_key");
                assert_eq!(s.admin_console_url, "https://10.0.0.1/admin");
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn imports_a_database_with_engine_and_credentials() {
        let overview = serde_json::json!({ "title": "prod-postgres" });
        let details = serde_json::json!({
            "sections": [{
                "title": "Database",
                "fields": [
                    { "title": "type", "value": { "menu": "postgres" } },
                    { "title": "server", "value": { "string": "db.prod.internal" } },
                    { "title": "port", "value": { "string": "5432" } },
                    { "title": "database", "value": { "string": "billing" } },
                    { "title": "username", "value": { "string": "app" } },
                    { "title": "password", "value": { "concealed": "rotate-me" } },
                    { "title": "SID", "value": { "string": "BILL" } },
                    { "title": "schema", "value": { "string": "public" } }
                ]
            }]
        });
        let payload = build_archive(&single_item_payload("102", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::Database(d) => {
                assert_eq!(d.database_type, "postgres");
                assert_eq!(d.server, "db.prod.internal");
                assert_eq!(d.port, Some(5432));
                assert_eq!(d.database_name, "billing");
                assert_eq!(d.username, "app");
                assert_eq!(d.password, "rotate-me");
                assert_eq!(d.sid, "BILL");
                assert_eq!(d.schema, "public");
            }
            other => panic!("expected Database, got {other:?}"),
        }
    }

    #[test]
    fn unknown_category_uuid_falls_through_to_passthrough() {
        // Defensive: any category code we don't recognize lands in the
        // passthrough ApiCredential mapping with raw_import carrying the
        // original code, so a future kind addition can identify it.
        let overview = serde_json::json!({ "title": "Mystery" });
        let details = serde_json::json!({ "sections": [{ "fields": [
            { "title": "field", "value": { "string": "value" } }
        ]}] });
        let payload = build_archive(&single_item_payload("999", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::ApiCredential(api) => {
                assert_eq!(api.raw_import["onepassword_category"], "999");
            }
            other => panic!("expected ApiCredential passthrough, got {other:?}"),
        }
    }

    #[test]
    fn bank_account_uuid_109_falls_through_to_passthrough() {
        // 1Password's 109 is WirelessRouter, not BankAccount. Confirm the
        // router does not classify it as BankAccount; it should fall to
        // the passthrough ApiCredential path with raw_import carrying the
        // unknown category so a future build_wireless_router can opt in.
        let overview = serde_json::json!({ "title": "Office router" });
        let details = serde_json::json!({
            "sections": [{ "fields": [
                { "title": "SSID", "value": { "string": "office-5g" } }
            ]}]
        });
        let payload = build_archive(&single_item_payload("109", overview, details));
        let items = import_1pux(&payload).unwrap();
        match &items[0].content {
            ItemContent::ApiCredential(api) => {
                assert_eq!(api.raw_import["onepassword_category"], "109");
            }
            other => panic!("expected ApiCredential passthrough, got {other:?}"),
        }
    }
}

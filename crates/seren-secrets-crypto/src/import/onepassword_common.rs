//! Shared loss-preserving 1Password item mapping. Parsers supply this intermediate;
//! category builders are shared by archive imports and CLI sync. Plaintext stays local.

use crate::import::otpauth::parse_otpauth_uri;
use crate::import::{
    ImportedAttachment, ImportedItem, custom_concealed_field, custom_string_field,
};
/// URI scheme that inline references to imported attachments use in
/// custom-field values. The destination client resolves the UUID against
/// `ImportedItem::attachments` to find the bytes. Kept identical to the
/// ProseMirror attachment scheme by re-exporting the shared constant.
pub use crate::prose::ATTACHMENT_URI_SCHEME;
use crate::prose::ZeroizableJson;
use crate::protocol::item::{
    ApiCredentialContent, ApiCredentialKind, BankAccountContent, CardContent, CryptoWalletContent,
    CustomField, DatabaseContent, DocumentContent, DriverLicenseContent, GovernmentId,
    IdentityContent, ItemContent, LoginContent, LoginUrl, PassportContent, PasswordHistoryEntry,
    PostalAddress, Section as ImportedSection, SecureNoteContent, ServerContent, SshKeyContent,
    TotpConfig, WalletAddress,
};
use crate::zeroize_ext::ZeroizableBTreeMap;

use jiff::Timestamp;

use std::collections::HashMap;

use uuid::Uuid;

pub(super) fn build_item(
    item: OnePasswordItem,
    collection: Option<String>,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let title = item.title.clone();
    let favorite = item.favorite;
    let tags = item.tags.clone();
    let category = item.category.code().to_owned();

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
    if item.cli {
        finish_cli(&item, &mut imported, attachments);
    }
    imported.title = title;
    imported.favorite = favorite;
    imported.tags = tags;
    imported.source_collection = collection;
    imported
}

fn item_notes(item: &OnePasswordItem) -> (crate::prose::ProseDoc, String) {
    crate::prose::from_plaintext(&item.notes)
}

fn build_login(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let (username, password) = login_credentials(item);
    let urls = collect_urls(item);
    let (custom_fields, totp, item_attachments) = section_fields_and_totp(item, attachments);
    let (notes, notes_text) = item_notes(item);

    let content = LoginContent {
        username,
        password,
        urls,
        totp,
        notes,
        notes_text,
        custom_fields,
        password_history: convert_password_history(&item.password_history),
        raw_import: ZeroizableJson::default(),
        ..Default::default()
    };
    let mut imported = ImportedItem::new_login("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_secure_note(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let (custom_fields, _, item_attachments) = section_fields_and_totp(item, attachments);
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

fn build_password(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let urls = collect_urls(item);
    let (custom_fields, totp, item_attachments) = section_fields_and_totp(item, attachments);
    let (notes, notes_text) = item_notes(item);
    let content = LoginContent {
        username: String::new(),
        password: item.password.clone(),
        urls,
        totp,
        notes,
        notes_text,
        custom_fields,
        password_history: convert_password_history(&item.password_history),
        raw_import: ZeroizableJson::default(),
        ..Default::default()
    };
    let mut imported = ImportedItem::new_login("", content);
    imported.attachments = item_attachments;
    imported
}

fn build_api_credential(
    item: &OnePasswordItem,
    category: &str,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let (mut custom_fields, _, item_attachments) = section_fields_and_totp(item, attachments);

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
        headers: ZeroizableBTreeMap::default(),
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
    item: &OnePasswordItem,
    category: &str,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let (custom_fields, _, item_attachments) = section_fields_and_totp(item, attachments);
    let (notes, notes_text) = item_notes(item);
    let content = ApiCredentialContent {
        kind: ApiCredentialKind::ApiKey,
        primary_value: String::new(),
        secondary_value: String::new(),
        headers: ZeroizableBTreeMap::default(),
        rotation: None,
        notes,
        notes_text,
        custom_fields,
        sections: Vec::new(),
        raw_import: serde_json::json!({
            "onepassword_category": category,
            "source": item.source.clone(),
        })
        .into(),
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
fn build_card(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let mut content = CardContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    for field in item.section_fields() {
        let title = field.label.clone();
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
fn build_identity(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let mut content = IdentityContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    for field in item.section_fields() {
        let title = field.label.clone();
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
fn build_document(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let mut content = DocumentContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    let mut primary_assigned = false;
    for field in item.section_fields() {
        let title = field.label.clone();
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
fn build_ssh_key(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
    let mut content = SshKeyContent::default();
    let mut leftover = Vec::new();
    let mut item_attachments = Vec::new();
    for field in item.section_fields() {
        let title = field.label.clone();
        let norm = normalize_field_title(&title);
        if let Some(inner) = extract_sshkey_value(&field.value) {
            if let Some(pk) = inner.get("privateKey").and_then(serde_json::Value::as_str) {
                content.private_key = pk.to_string();
            }
            if let Some(meta) = inner.get("metadata") {
                if let Some(pub_key) = meta.get("publicKey").and_then(serde_json::Value::as_str) {
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
pub(super) fn normalize_field_title(title: &str) -> String {
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
fn login_credentials(item: &OnePasswordItem) -> (String, String) {
    let mut username = String::new();
    let mut password = String::new();
    for field in item.fields.iter().filter(|f| f.login_field) {
        let designation = field.purpose.as_deref().unwrap_or("");
        let name = field.id.as_str();
        let value = scalar_value(&field.value);
        let is_username =
            designation.eq_ignore_ascii_case("username") || name.eq_ignore_ascii_case("username");
        let is_password = designation.eq_ignore_ascii_case("password")
            || name.eq_ignore_ascii_case("password")
            || field.password_fallback;
        if is_username && username.is_empty() {
            username = value;
        } else if is_password && password.is_empty() {
            password = value;
        }
    }
    (username, password)
}

fn collect_urls(item: &OnePasswordItem) -> Vec<LoginUrl> {
    item.urls
        .iter()
        .map(|u| LoginUrl {
            url: u.href.clone(),
            match_type: None,
            label: u.label.clone(),
            primary: u.primary,
        })
        .collect()
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
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> (
    Vec<CustomField>,
    Option<TotpConfig>,
    Vec<ImportedAttachment>,
) {
    let mut fields = Vec::new();
    let mut totp = None;
    let mut item_attachments = Vec::new();
    for field in item.section_fields() {
        let name = field.label.clone();
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
    (fields, totp, item_attachments)
}

fn convert_password_history(history: &[OnePasswordHistory]) -> Vec<PasswordHistoryEntry> {
    let mut history: Vec<&OnePasswordHistory> = history
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

fn onepassword_raw_import(item: &OnePasswordItem, category: &str) -> ZeroizableJson {
    if item.password_history.is_empty() {
        return serde_json::json!({ "onepassword_category": category }).into();
    }
    let history: Vec<serde_json::Value> = item
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
        return serde_json::json!({ "onepassword_category": category }).into();
    }
    serde_json::json!({
        "onepassword_category": category,
        "password_history": history,
    })
    .into()
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
        let new_id = raw.stable_id.unwrap_or_else(Uuid::new_v4);
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

fn import_sections(item: &OnePasswordItem) -> Vec<ImportedSection> {
    item.sections
        .iter()
        .filter(|s| !s.id.is_empty())
        .map(|s| ImportedSection {
            id: s.id.clone(),
            title: s.label.clone(),
        })
        .collect()
}

fn for_each_field(
    item: &OnePasswordItem,
    mut visit: impl FnMut(&str, String, String, &serde_json::Value),
) {
    for field in item.section_fields() {
        visit(
            field.section_id.as_deref().unwrap_or(""),
            normalize_field_title(&field.label),
            field.label.clone(),
            &field.value,
        );
    }
}

fn build_bank_account(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
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

fn build_passport(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
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
            "expirydate" if item.cli && !v.is_empty() => content.expires_on = Some(v),
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

fn build_driver_license(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
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
            "expirydate" if item.cli && !v.is_empty() => content.expires_on = Some(v),
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

fn build_crypto_wallet(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
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

fn build_server(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
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

fn build_database(
    item: &OnePasswordItem,
    attachments: &HashMap<String, RawAttachment>,
) -> ImportedItem {
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
            id: raw.stable_id.unwrap_or_else(Uuid::new_v4),
            filename: raw.filename.clone(),
            content_type: None,
            data: raw.data.clone(),
        });
    }
}

/// Categories shared by CLI names and archive codes. CUSTOM is deliberately unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnePasswordCategory {
    Login,
    CreditCard,
    SecureNote,
    Identity,
    Password,
    Document,
    BankAccount,
    Database,
    DriverLicense,
    Passport,
    Server,
    ApiCredential,
    SshKey,
    CryptoWallet,
    SoftwareLicense,
    Membership,
    RewardProgram,
    WirelessRouter,
    EmailAccount,
    OutdoorLicense,
    SocialSecurityNumber,
    MedicalRecord,
    Unknown(String),
}

impl OnePasswordCategory {
    pub fn from_name(name: &str) -> Self {
        match normalize_field_title(name).as_str() {
            "001" | "login" => Self::Login,
            "002" | "creditcard" => Self::CreditCard,
            "003" | "securenote" => Self::SecureNote,
            "004" | "identity" => Self::Identity,
            "005" | "password" => Self::Password,
            "006" | "document" => Self::Document,
            "100" | "softwarelicense" => Self::SoftwareLicense,
            "101" | "bankaccount" => Self::BankAccount,
            "102" | "database" => Self::Database,
            "103" | "driverlicense" => Self::DriverLicense,
            "104" | "outdoorlicense" => Self::OutdoorLicense,
            "105" | "membership" => Self::Membership,
            "106" | "passport" => Self::Passport,
            "107" | "rewardprogram" => Self::RewardProgram,
            "108" | "socialsecuritynumber" => Self::SocialSecurityNumber,
            "109" | "wirelessrouter" => Self::WirelessRouter,
            "110" | "server" => Self::Server,
            "111" | "emailaccount" => Self::EmailAccount,
            "112" | "apicredential" => Self::ApiCredential,
            "113" | "medicalrecord" => Self::MedicalRecord,
            "114" | "sshkey" => Self::SshKey,
            "115" | "cryptowallet" => Self::CryptoWallet,
            _ => Self::Unknown(name.to_owned()),
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Login => "001",
            Self::CreditCard => "002",
            Self::SecureNote => "003",
            Self::Identity => "004",
            Self::Password => "005",
            Self::Document => "006",
            Self::SoftwareLicense => "100",
            Self::BankAccount => "101",
            Self::Database => "102",
            Self::DriverLicense => "103",
            Self::OutdoorLicense => "104",
            Self::Membership => "105",
            Self::Passport => "106",
            Self::RewardProgram => "107",
            Self::SocialSecurityNumber => "108",
            Self::WirelessRouter => "109",
            Self::Server => "110",
            Self::EmailAccount => "111",
            Self::ApiCredential => "112",
            Self::MedicalRecord => "113",
            Self::SshKey => "114",
            Self::CryptoWallet => "115",
            Self::Unknown(name) => name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnePasswordFieldKind {
    String,
    Concealed,
    Email,
    Url,
    Otp,
    Date,
    MonthYear,
    Phone,
    Menu,
    Address,
    SshKey,
    CreditCardNumber,
    CreditCardType,
    Reference,
    File,
    Unknown(String),
}

impl OnePasswordFieldKind {
    pub(super) fn from_tag(tag: &str) -> Self {
        match normalize_field_title(tag).as_str() {
            "string" => Self::String,
            "concealed" => Self::Concealed,
            "email" => Self::Email,
            "url" => Self::Url,
            "otp" | "totp" => Self::Otp,
            "date" => Self::Date,
            "monthyear" => Self::MonthYear,
            "phone" => Self::Phone,
            "menu" => Self::Menu,
            "address" => Self::Address,
            "sshkey" => Self::SshKey,
            "creditcardnumber" => Self::CreditCardNumber,
            "creditcardtype" => Self::CreditCardType,
            "reference" => Self::Reference,
            "file" => Self::File,
            _ => Self::Unknown(tag.to_owned()),
        }
    }

    pub(super) fn tag(&self) -> &str {
        match self {
            Self::String => "string",
            Self::Concealed => "concealed",
            Self::Email => "email",
            Self::Url => "url",
            Self::Otp => "totp",
            Self::Date => "date",
            Self::MonthYear => "monthYear",
            Self::Phone => "phone",
            Self::Menu => "menu",
            Self::Address => "address",
            Self::SshKey => "sshKey",
            Self::CreditCardNumber => "creditCardNumber",
            Self::CreditCardType => "creditCardType",
            Self::Reference => "reference",
            Self::File => "file",
            Self::Unknown(tag) => tag,
        }
    }
}

/// The plaintext intermediate. Debug deliberately never emits item data.
pub struct OnePasswordItem {
    pub uuid: String,
    pub category: OnePasswordCategory,
    pub title: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub urls: Vec<OnePasswordUrl>,
    pub notes: String,
    pub sections: Vec<OnePasswordSection>,
    pub fields: Vec<OnePasswordField>,
    pub files: Vec<OnePasswordFile>,
    pub password_history: Vec<OnePasswordHistory>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub version: Option<u64>,
    pub(super) source: serde_json::Value,
    pub(super) password: String,
    pub(super) cli: bool,
}

pub struct OnePasswordUrl {
    pub label: Option<String>,
    pub primary: Option<bool>,
    pub href: String,
}
pub struct OnePasswordSection {
    pub id: String,
    pub label: String,
}
pub struct OnePasswordField {
    pub id: String,
    pub section_id: Option<String>,
    pub kind: OnePasswordFieldKind,
    pub purpose: Option<String>,
    pub label: String,
    /// Tagged value shared with the archive classifier. The CLI parser supplies the tag.
    pub value: serde_json::Value,
    pub totp_uri: Option<String>,
    pub(super) login_field: bool,
    pub(super) password_fallback: bool,
}
pub struct OnePasswordFile {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub bytes: Vec<u8>,
}
pub struct OnePasswordHistory {
    pub value: String,
    pub time: Option<i64>,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+ };
}
redacted_debug!(
    OnePasswordItem,
    OnePasswordUrl,
    OnePasswordSection,
    OnePasswordField,
    OnePasswordFile,
    OnePasswordHistory
);

impl OnePasswordItem {
    fn section_fields(&self) -> impl Iterator<Item = &OnePasswordField> {
        self.fields.iter().filter(|f| {
            !f.login_field
                && !f
                    .purpose
                    .as_deref()
                    .is_some_and(|p| p.eq_ignore_ascii_case("NOTES"))
        })
    }

    /// Map this parsed item using the same builders as `.1pux`.
    /// CLI attachment references are stable within this source item; archive imports
    /// continue assigning fresh UUIDs for each reference as before.
    pub fn into_imported(self) -> ImportedItem {
        let attachments = self
            .files
            .iter()
            .map(|file| {
                let namespace = Uuid::new_v5(
                    &Uuid::NAMESPACE_URL,
                    format!("1password:item:{}", self.uuid).as_bytes(),
                );
                (
                    file.id.clone(),
                    RawAttachment {
                        filename: file.name.clone(),
                        data: file.bytes.clone(),
                        stable_id: self
                            .cli
                            .then(|| Uuid::new_v5(&namespace, file.id.as_bytes())),
                    },
                )
            })
            .collect();
        build_item(self, None, &attachments)
    }
}

pub(super) struct RawAttachment {
    pub filename: String,
    pub data: Vec<u8>,
    pub stable_id: Option<Uuid>,
}

/// Apply CLI metadata only after the shared typed mapping. Archive output remains
/// unchanged; CLI fields additionally retain their source section, kind and purpose.
fn finish_cli(
    item: &OnePasswordItem,
    imported: &mut ImportedItem,
    attachments: &HashMap<String, RawAttachment>,
) {
    use crate::protocol::item::{CustomFieldKind, FieldPurpose};
    let (raw, custom, sections) = imported.content.import_metadata_mut();
    if !raw.is_object() {
        *raw = serde_json::json!({"onepassword_category": item.category.code()}).into();
    }
    *sections = import_sections(item);
    let mut used = std::collections::HashSet::new();
    for field in item.section_fields() {
        let mut matched_attachments = Vec::new();
        let classified = classify_value(&field.value, attachments, &mut matched_attachments);
        let value = match classified {
            ClassifiedValue::String(s)
            | ClassifiedValue::Concealed(s)
            | ClassifiedValue::Totp(s) => s,
        };
        let position = custom
            .iter()
            .enumerate()
            .find(|(i, c)| {
                !used.contains(i)
                    && c.name == field.label
                    && (c.value == value || field.kind == OnePasswordFieldKind::File)
            })
            .map(|(i, _)| i);
        let position = position.or_else(|| {
            // Non-Login typed kinds have no TOTP slot. Never discard the URI.
            // File fields also need a resolvable inline reference on every kind.
            let primary_document_file = matches!(item.category, OnePasswordCategory::Document)
                && imported
                    .attachments
                    .first()
                    .is_some_and(|a| matched_attachments.first().is_some_and(|m| m.id == a.id));
            if field.kind == OnePasswordFieldKind::Otp
                && !matches!(
                    item.category,
                    OnePasswordCategory::Login | OnePasswordCategory::Password
                )
                || field.kind == OnePasswordFieldKind::File && !primary_document_file
            {
                custom.push(custom_string_field(field.label.clone(), value.clone()));
                Some(custom.len() - 1)
            } else {
                None
            }
        });
        if let Some(i) = position {
            used.insert(i);
            let c = &mut custom[i];
            c.value = value;
            c.section_id = field.section_id.clone().filter(|s| !s.is_empty());
            c.kind = match field.kind {
                OnePasswordFieldKind::Concealed
                | OnePasswordFieldKind::Otp
                | OnePasswordFieldKind::SshKey => CustomFieldKind::Concealed,
                OnePasswordFieldKind::Url => CustomFieldKind::Url,
                OnePasswordFieldKind::Email => CustomFieldKind::Email,
                OnePasswordFieldKind::Date => CustomFieldKind::Date,
                _ => CustomFieldKind::String,
            };
            c.purpose = match field.purpose.as_deref() {
                Some("USERNAME") => Some(FieldPurpose::Username),
                Some("PASSWORD") => Some(FieldPurpose::Password),
                Some("NOTES") => Some(FieldPurpose::Notes),
                _ if field.kind == OnePasswordFieldKind::Otp => Some(FieldPurpose::Otp),
                _ => None,
            };
        }
        for attachment in matched_attachments {
            if !imported.attachments.iter().any(|a| a.id == attachment.id) {
                imported.attachments.push(attachment);
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    imported.attachments.retain(|a| seen.insert(a.id));
}

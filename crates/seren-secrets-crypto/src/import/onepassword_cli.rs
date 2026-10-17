//! Pure parser for `op item get --format json` and already-downloaded file bytes.
//! No process, network or filesystem access. Errors and Debug never include plaintext.
use super::onepassword_common::*;
use crate::{CryptoError, CryptoResult};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Deserialize)]
struct CliItem {
    id: String,
    category: String,
    title: String,
    version: u64,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    urls: Vec<CliUrl>,
    #[serde(default)]
    sections: Vec<CliSection>,
    #[serde(default)]
    fields: Vec<CliField>,
    #[serde(default)]
    files: Vec<CliFile>,
    #[serde(default)]
    password_history: Vec<CliHistory>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}
#[derive(Deserialize)]
struct CliUrl {
    href: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    primary: Option<bool>,
}
#[derive(Deserialize)]
struct CliSection {
    id: String,
    #[serde(default)]
    label: Option<String>,
}
#[derive(Deserialize)]
struct CliField {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    section: Option<CliSection>,
    #[serde(default)]
    value: Value,
}
#[derive(Deserialize)]
struct CliFile {
    id: String,
    name: String,
    size: u64,
    #[serde(default)]
    section: Option<CliSection>,
}
#[derive(Deserialize)]
struct CliHistory {
    value: String,
    time: Value,
}

/// Parse one complete CLI item. Each declared file must have matching downloaded
/// bytes; an incomplete download is refused before a sync can hash or write it.
/// The `totp` display code is deliberately not read: `value` is the durable URI.
pub fn parse_cli_item(json: &[u8], files: &[(String, Vec<u8>)]) -> CryptoResult<OnePasswordItem> {
    let invalid = || CryptoError::Import("invalid 1Password CLI item");
    let source: Value = serde_json::from_slice(json).map_err(|_| invalid())?;
    let cli: CliItem = serde_json::from_value(source.clone()).map_err(|_| invalid())?;
    if cli.id.is_empty() || cli.category.is_empty() {
        return Err(invalid());
    }
    let category = OnePasswordCategory::from_name(&cli.category);
    let is_login = matches!(
        category,
        OnePasswordCategory::Login | OnePasswordCategory::Password
    );
    let mut sections = Vec::new();
    for s in cli.sections {
        add_section(&mut sections, s);
    }
    let mut fields = Vec::new();
    let mut notes = String::new();
    let mut password = String::new();
    for f in cli.fields {
        let kind = OnePasswordFieldKind::from_tag(&f.kind);
        let purpose = f.purpose.as_deref().unwrap_or("");
        if purpose.eq_ignore_ascii_case("NOTES") {
            notes = string_value(&f.value);
        }
        if purpose.eq_ignore_ascii_case("PASSWORD") && password.is_empty() {
            password = string_value(&f.value);
        }
        let login_field = is_login
            && (purpose.eq_ignore_ascii_case("USERNAME")
                || purpose.eq_ignore_ascii_case("PASSWORD"));
        let section_id = f.section.as_ref().map(|s| s.id.clone());
        if let Some(section) = f.section {
            add_section(&mut sections, section);
        }
        let totp_uri = (kind == OnePasswordFieldKind::Otp).then(|| string_value(&f.value));
        let value = if kind == OnePasswordFieldKind::SshKey && f.value.is_string() {
            serde_json::json!({"sshKey": {"privateKey": f.value}})
        } else {
            serde_json::json!({kind.tag(): f.value})
        };
        fields.push(OnePasswordField {
            id: f.id.clone(),
            section_id,
            kind,
            purpose: f.purpose,
            label: f.label.filter(|s| !s.is_empty()).unwrap_or(f.id),
            value,
            totp_uri,
            login_field,
            password_fallback: false,
        });
    }
    let mut seen = HashSet::new();
    if files
        .iter()
        .any(|(id, _)| id.is_empty() || !seen.insert(id))
    {
        return Err(CryptoError::Import("duplicate 1Password file bytes"));
    }
    let mut normalized_files = Vec::new();
    let mut declared = HashSet::new();
    for f in cli.files {
        if f.id.is_empty() || !declared.insert(f.id.clone()) {
            return Err(invalid());
        }
        let bytes = files
            .iter()
            .find(|(id, _)| id == &f.id)
            .map(|(_, bytes)| bytes)
            .ok_or(CryptoError::Import("missing 1Password file bytes"))?;
        if bytes.len() as u64 != f.size {
            return Err(CryptoError::Import("1Password file size mismatch"));
        }
        let section_id = f.section.as_ref().map(|s| s.id.clone());
        if let Some(s) = f.section {
            add_section(&mut sections, s);
        }
        // Top-level files are references even when the CLI emits no FILE field.
        if !fields.iter().any(|field| {
            field.kind == OnePasswordFieldKind::File
                && (field.id == f.id
                    || field.value.get("file").and_then(Value::as_str) == Some(f.id.as_str())
                    || field
                        .value
                        .get("file")
                        .and_then(|v| v.get("id").or_else(|| v.get("documentId")))
                        .and_then(Value::as_str)
                        == Some(&f.id))
        }) {
            fields.push(OnePasswordField {
                id: f.id.clone(),
                section_id,
                kind: OnePasswordFieldKind::File,
                purpose: None,
                label: f.name.clone(),
                value: serde_json::json!({"file": {"id": f.id, "fileName": f.name}}),
                totp_uri: None,
                login_field: false,
                password_fallback: false,
            });
        }
        normalized_files.push(OnePasswordFile {
            id: f.id,
            name: f.name,
            size: f.size,
            bytes: bytes.clone(),
        });
    }
    // A FILE field may encode its id as a scalar; resolve it through the same pool.
    for field in &mut fields {
        if field.kind == OnePasswordFieldKind::File {
            let value = &field.value["file"];
            let id = value
                .as_str()
                .or_else(|| {
                    value
                        .get("id")
                        .or_else(|| value.get("documentId"))
                        .and_then(Value::as_str)
                })
                .unwrap_or(&field.id);
            let file = normalized_files
                .iter()
                .find(|f| f.id == id)
                .ok_or(CryptoError::Import("unknown 1Password file reference"))?;
            field.value = serde_json::json!({"file": {"id": file.id, "fileName": file.name}});
        }
    }
    let mut history = Vec::new();
    for h in cli.password_history {
        let time = if let Some(time) = h.time.as_i64() {
            time
        } else if let Some(text) = h.time.as_str() {
            text.parse::<jiff::Timestamp>()
                .map_err(|_| invalid())?
                .as_second()
        } else {
            return Err(invalid());
        };
        history.push(OnePasswordHistory {
            value: h.value,
            time: Some(time),
        });
    }
    Ok(OnePasswordItem {
        uuid: cli.id,
        category,
        title: cli.title,
        favorite: cli.favorite,
        tags: cli.tags,
        urls: cli
            .urls
            .into_iter()
            .map(|u| OnePasswordUrl {
                label: u.label,
                primary: u.primary,
                href: u.href,
            })
            .collect(),
        notes,
        sections,
        fields,
        files: normalized_files,
        password_history: history,
        created_at: cli.created_at,
        updated_at: cli.updated_at,
        version: Some(cli.version),
        source,
        password,
        cli: true,
    })
}

fn string_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        _ => v.to_string(),
    }
}
fn add_section(sections: &mut Vec<OnePasswordSection>, section: CliSection) {
    if let Some(existing) = sections.iter_mut().find(|s| s.id == section.id) {
        if let Some(label) = section.label {
            existing.label = label;
        }
    } else {
        sections.push(OnePasswordSection {
            label: section.label.unwrap_or_else(|| section.id.clone()),
            id: section.id,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::{CustomFieldKind, ItemContent};
    use crate::sync_binding::content_hash;
    use serde_json::json;

    // Captured redacted objects; synthetic values below cover fields whose values
    // were absent or redacted in the capture (TOTP, file bytes and history).
    const FIXTURES: &[(&str, &str, &str)] = &[
        (
            "API_CREDENTIAL",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-api-credential.json"),
        ),
        (
            "BANK_ACCOUNT",
            "bank_account",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-bank-account.json"),
        ),
        (
            "CREDIT_CARD",
            "card",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-credit-card.json"),
        ),
        (
            "CUSTOM",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-custom.json"),
        ),
        (
            "DATABASE",
            "database",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-database.json"),
        ),
        (
            "DOCUMENT",
            "document",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-document.json"),
        ),
        (
            "DRIVER_LICENSE",
            "driver_license",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-driver-license.json"),
        ),
        (
            "EMAIL_ACCOUNT",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-email-account.json"),
        ),
        (
            "IDENTITY",
            "identity",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-identity.json"),
        ),
        (
            "LOGIN",
            "login",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-login.json"),
        ),
        (
            "MEDICAL_RECORD",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-medical-record.json"),
        ),
        (
            "MEMBERSHIP",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-membership.json"),
        ),
        (
            "OUTDOOR_LICENSE",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-outdoor-license.json"),
        ),
        (
            "PASSPORT",
            "passport",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-passport.json"),
        ),
        (
            "PASSWORD",
            "login",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-password.json"),
        ),
        (
            "REWARD_PROGRAM",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-reward-program.json"),
        ),
        (
            "SECURE_NOTE",
            "secure_note",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-secure-note.json"),
        ),
        (
            "SERVER",
            "server",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-server.json"),
        ),
        (
            "SOCIAL_SECURITY_NUMBER",
            "api_credential",
            include_str!(
                "../../tests/fixtures/onepassword-cli/item-get-social-security-number.json"
            ),
        ),
        (
            "SOFTWARE_LICENSE",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-software-license.json"),
        ),
        (
            "SSH_KEY",
            "ssh_key",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-ssh-key.json"),
        ),
        (
            "WIRELESS_ROUTER",
            "api_credential",
            include_str!("../../tests/fixtures/onepassword-cli/item-get-wireless-router.json"),
        ),
    ];

    fn fixture(category: &str) -> Value {
        serde_json::from_str(FIXTURES.iter().find(|(c, _, _)| *c == category).unwrap().2).unwrap()
    }
    fn imported(mut json: Value) -> crate::import::ImportedItem {
        let mut files = Vec::new();
        if let Some(declared) = json.get_mut("files").and_then(Value::as_array_mut) {
            for file in declared {
                let bytes = b"synthetic file\0bytes".to_vec();
                file["size"] = json!(bytes.len());
                files.push((file["id"].as_str().unwrap().to_owned(), bytes));
            }
        }
        parse_cli_item(&serde_json::to_vec(&json).unwrap(), &files)
            .unwrap()
            .into_imported()
    }
    fn set_field(json: &mut Value, id: &str, value: Value) {
        json["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|f| f["id"] == id)
            .unwrap()["value"] = value;
    }

    #[test]
    fn all_captured_categories_share_mapping_and_have_stable_content() {
        assert_eq!(FIXTURES.len(), 22);
        for (category, expected, text) in FIXTURES {
            let raw: Value = serde_json::from_str(text).unwrap();
            let first = imported(raw.clone());
            let second = imported(raw.clone());
            let content = serde_json::to_value(&first.content).unwrap();
            assert_eq!(content["kind"], *expected, "{category}");
            assert_eq!(first.title, raw["title"].as_str().unwrap());
            assert!(content["raw_import"].is_object(), "{category}");
            assert_eq!(first, second, "{category}");
            assert_eq!(
                content_hash(&first.title, &first.tags, first.favorite, &first.content),
                content_hash(
                    &second.title,
                    &second.tags,
                    second.favorite,
                    &second.content
                )
            );
            if *expected == "api_credential" && *category != "API_CREDENTIAL" {
                // The test helper changes only downloaded file sizes; these
                // passthrough captures have no files.
                assert_eq!(content["raw_import"]["source"], raw);
            }
            let human = category
                .split('_')
                .map(|s| {
                    let mut c = s.chars();
                    c.next().unwrap().to_string() + &c.as_str().to_ascii_lowercase()
                })
                .collect::<Vec<_>>()
                .join(" ");
            if *category != "CUSTOM" {
                assert_eq!(
                    OnePasswordCategory::from_name(category),
                    OnePasswordCategory::from_name(&human)
                );
            }
        }
        assert_eq!(
            OnePasswordCategory::from_name("Crypto Wallet"),
            OnePasswordCategory::CryptoWallet
        );
    }

    #[test]
    fn login_fields_urls_totp_sections_notes_and_history_are_retained() {
        let mut raw = fixture("LOGIN");
        raw["favorite"] = json!(true);
        raw["tags"] = json!(["fixture tag"]);
        raw["urls"] = json!([{"href":"https://secondary.invalid","label":"second","primary":false},{"href":"https://primary.invalid","label":"main","primary":true}]);
        set_field(&mut raw, "username", json!("fixture-user"));
        set_field(&mut raw, "password", json!("fixture-password"));
        set_field(&mut raw, "notesPlain", json!("fixture notes\nsecond line"));
        let otp = raw["fields"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|f| f["type"] == "OTP")
            .unwrap();
        otp["value"] = json!(
            "otpauth://totp/fixture?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=45"
        );
        raw["password_history"] = json!([{"value":"older-fixture","time":1700000000},{"value":"newer-fixture","time":"2024-01-01T00:00:00Z"}]);
        let item = imported(raw.clone());
        let ItemContent::Login(login) = &item.content else {
            panic!("wrong kind")
        };
        assert_eq!(login.username, "fixture-user");
        assert_eq!(login.password, "fixture-password");
        assert_eq!(login.urls[1].primary, Some(true));
        assert_eq!(login.urls[1].label.as_deref(), Some("main"));
        assert_eq!(login.urls[1].url, "https://primary.invalid");
        let totp = serde_json::to_value(login.totp.as_ref().unwrap()).unwrap();
        assert_eq!(totp["secret_base32"], "JBSWY3DPEHPK3PXP");
        assert_eq!(totp["algorithm"], "SHA256");
        assert_eq!(totp["digits"], 8);
        assert_eq!(totp["period_seconds"], 45);
        assert_eq!(login.notes_text, "fixture notes\nsecond line");
        assert_eq!(login.password_history[0].password, "newer-fixture");
        assert_eq!(login.password_history[1].password, "older-fixture");
        assert_eq!(login.password_history[0].changed_at, "2024-01-01T00:00:00Z");
        let url = login
            .custom_fields
            .iter()
            .find(|f| f.name == "Custom URL")
            .unwrap();
        assert_eq!(url.kind, CustomFieldKind::Url);
        assert!(
            login
                .sections
                .iter()
                .any(|s| Some(&s.id) == url.section_id.as_ref())
        );
        assert_eq!(item.attachments[0].data, b"synthetic file\0bytes");
        assert!(
            login
                .custom_fields
                .iter()
                .any(|f| f.value.contains(&item.attachments[0].id.to_string()))
        );
        assert_eq!(item.tags, ["fixture tag"]);
        assert!(item.favorite);
        let before = content_hash(&item.title, &item.tags, item.favorite, &item.content);
        set_field(&mut raw, "password", json!("changed-fixture"));
        let changed = imported(raw);
        assert_ne!(
            before,
            content_hash(
                &changed.title,
                &changed.tags,
                changed.favorite,
                &changed.content
            )
        );
    }

    #[test]
    fn typed_card_ssh_document_and_other_field_kinds_survive() {
        for (category, source, target) in [
            ("API_CREDENTIAL", "credential", "primary_value"),
            ("BANK_ACCOUNT", "accountNo", "account_number"),
            ("DATABASE", "database", "database_name"),
            ("DRIVER_LICENSE", "number", "number"),
            ("DRIVER_LICENSE", "expiry_date", "expires_on"),
            ("IDENTITY", "firstname", "first_name"),
            ("PASSPORT", "number", "number"),
            ("PASSPORT", "expiry_date", "expires_on"),
            ("PASSWORD", "password", "password"),
            ("SERVER", "username", "username"),
            ("SECURE_NOTE", "notesPlain", "body_text"),
        ] {
            let mut raw = fixture(category);
            set_field(&mut raw, source, json!("synthetic-value"));
            let item = imported(raw);
            let body = serde_json::to_value(&item.content).unwrap();
            assert_eq!(body[target], "synthetic-value", "{category}/{source}");
        }
        let mut wallet = fixture("CUSTOM");
        wallet["category"] = json!("Crypto Wallet");
        set_field(
            &mut wallet,
            "recoveryPhrase",
            json!("synthetic recovery phrase"),
        );
        let item = imported(wallet);
        let ItemContent::CryptoWallet(wallet) = item.content else {
            panic!("wrong kind")
        };
        assert_eq!(wallet.seed_phrase, "synthetic recovery phrase");
        let mut card = fixture("CREDIT_CARD");
        set_field(&mut card, "ccnum", json!("4111111111111111"));
        set_field(&mut card, "expiry", json!("203012"));
        let item = imported(card);
        let ItemContent::Card(card) = item.content else {
            panic!("wrong kind")
        };
        assert_eq!(card.number, "4111111111111111");
        assert_eq!(card.expiry, "203012");
        let mut ssh = fixture("SSH_KEY");
        set_field(&mut ssh, "private_key", json!("synthetic-private-key"));
        set_field(&mut ssh, "public_key", json!("synthetic-public-key"));
        let item = imported(ssh);
        let ItemContent::SshKey(key) = item.content else {
            panic!("wrong kind")
        };
        assert_eq!(key.private_key, "synthetic-private-key");
        assert_eq!(key.public_key, "synthetic-public-key");
        let mut document = fixture("DOCUMENT");
        let file_id = document["files"][0]["id"].clone();
        document["fields"].as_array_mut().unwrap().push(
            json!({"id":"file-reference", "label":"document", "type":"FILE", "value":file_id}),
        );
        let item = imported(document);
        let ItemContent::Document(doc) = item.content else {
            panic!("wrong kind")
        };
        assert_eq!(item.attachments.len(), 1);
        assert_eq!(item.attachments[0].data, b"synthetic file\0bytes");
        assert!(
            doc.attachment_uri
                .ends_with(&item.attachments[0].id.to_string())
        );
        assert_eq!(doc.filename, item.attachments[0].filename);
        let mut raw = fixture("LOGIN");
        for (id, kind, value) in [
            ("ref", "REFERENCE", json!("source-reference")),
            ("menu", "MENU", json!("choice")),
            (
                "address",
                "ADDRESS",
                json!({"street":"synthetic street","city":"synthetic city"}),
            ),
        ] {
            raw["fields"].as_array_mut().unwrap().push(json!({"id":id,"label":id,"type":kind,"value":value,"section":{"id":"extra","label":"Extra"}}));
        }
        let item = imported(raw);
        let ItemContent::Login(login) = item.content else {
            panic!("wrong kind")
        };
        for (name, value) in [
            ("ref", "source-reference"),
            ("menu", "choice"),
            ("address", "synthetic street, synthetic city"),
        ] {
            assert!(login.custom_fields.iter().any(|f| f.name == name
                && f.value == value
                && f.section_id.as_deref() == Some("extra")));
        }
    }

    #[test]
    fn unknown_source_is_intact_and_incomplete_files_fail_without_content() {
        let mut raw = fixture("CUSTOM");
        raw["category"] = json!("future-category");
        raw["future"] = json!({"unchanged":[1,"fixture"]});
        let item = imported(raw.clone());
        let ItemContent::ApiCredential(body) = item.content else {
            panic!("wrong kind")
        };
        assert_eq!(body.raw_import["source"], raw);
        let document = fixture("DOCUMENT");
        assert_eq!(
            parse_cli_item(&serde_json::to_vec(&document).unwrap(), &[])
                .unwrap_err()
                .to_string(),
            "import error: missing 1Password file bytes"
        );
        assert_eq!(
            parse_cli_item(br#"{"id":"synthetic-secret"}"#, &[])
                .unwrap_err()
                .to_string(),
            "import error: invalid 1Password CLI item"
        );
    }
}

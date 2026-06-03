//! Generic CSV importer.
//!
//! Importers like LastPass, KeePass, Dashlane, and Apple iCloud Passwords all
//! emit slightly different CSV column sets. The caller supplies a
//! `CsvColumnMapping` describing which source columns hold which fields.
//! Unknown columns are preserved as custom fields so nothing is silently lost.

use super::ImportedItem;
use crate::error::{CryptoError, CryptoResult};
use crate::protocol::item::{LoginContent, TotpAlgorithm, TotpConfig};

#[derive(Debug, Clone, Default)]
pub struct CsvColumnMapping {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    /// Optional source-folder column used to populate `source_collection`.
    pub folder: Option<String>,
    /// Columns to ignore entirely (e.g. internal IDs from the source tool).
    pub skip: Vec<String>,
}

impl CsvColumnMapping {
    /// Standard LastPass mapping: `name,url,username,password,extra,grouping,fav`.
    pub fn lastpass() -> Self {
        Self {
            title: Some("name".into()),
            url: Some("url".into()),
            username: Some("username".into()),
            password: Some("password".into()),
            notes: Some("extra".into()),
            folder: Some("grouping".into()),
            skip: vec!["fav".into()],
            ..Default::default()
        }
    }

    /// Standard KeePass mapping: `Title,Username,Password,URL,Notes`.
    pub fn keepass() -> Self {
        Self {
            title: Some("Title".into()),
            username: Some("Username".into()),
            password: Some("Password".into()),
            url: Some("URL".into()),
            notes: Some("Notes".into()),
            ..Default::default()
        }
    }

    /// Auto-detect a mapping from the header row using case-insensitive matches
    /// against the common conventions of multiple tools.
    ///
    /// When multiple synonyms appear (e.g. both `email` and `username`), the
    /// canonical column wins regardless of header order. `username` beats
    /// `email`/`user`/`login`; `title` beats `name`/`item name`; and so on.
    pub fn autodetect(headers: &[&str]) -> Self {
        let mut m = Self::default();

        // Pick the best header for a field by scanning synonyms in priority
        // order and returning the first synonym present in the headers.
        let pick = |synonyms: &[&str]| -> Option<String> {
            for syn in synonyms {
                if let Some(h) = headers.iter().find(|h| h.eq_ignore_ascii_case(syn)) {
                    return Some((*h).to_string());
                }
            }
            None
        };

        m.title = pick(&["title", "name", "item name"]);
        m.username = pick(&["username", "user", "login", "email"]);
        m.password = pick(&["password"]);
        m.url = pick(&["url", "website", "site", "uri"]);
        m.notes = pick(&["notes", "extra", "memo"]);
        m.totp_secret = pick(&["totp", "otpauth", "otp", "2fa", "two factor"]);
        m.folder = pick(&["folder", "grouping", "category", "vault"]);
        m
    }
}

/// Parse a CSV payload into a stream of `ImportedItem`s.
/// Returns `(items, errors)` where `errors` is per-row failures keyed by 1-based row number.
pub fn import_csv(
    csv_text: &str,
    mapping: &CsvColumnMapping,
) -> (Vec<ImportedItem>, Vec<(usize, CryptoError)>) {
    let mut items = Vec::new();
    let mut errors = Vec::new();

    let mut rows = parse_csv(csv_text);
    let Some(headers) = rows.next() else {
        return (items, errors);
    };

    for (idx, row) in rows.enumerate() {
        match build_item(&headers, &row, mapping) {
            Ok(Some(item)) => items.push(item),
            Ok(None) => {} // empty row
            Err(err) => errors.push((idx + 2, err)),
        }
    }
    (items, errors)
}

fn build_item(
    headers: &[String],
    row: &[String],
    mapping: &CsvColumnMapping,
) -> CryptoResult<Option<ImportedItem>> {
    if row.iter().all(|c| c.trim().is_empty()) {
        return Ok(None);
    }

    let value_for = |name: &str| -> Option<&str> {
        headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case(name))
            .and_then(|i| row.get(i))
            .map(String::as_str)
            .filter(|s| !s.is_empty())
    };

    let title = mapping
        .title
        .as_deref()
        .and_then(value_for)
        .unwrap_or("Imported")
        .to_string();
    let username = mapping
        .username
        .as_deref()
        .and_then(value_for)
        .unwrap_or("")
        .to_string();
    let password = mapping
        .password
        .as_deref()
        .and_then(value_for)
        .unwrap_or("")
        .to_string();
    let notes = mapping
        .notes
        .as_deref()
        .and_then(value_for)
        .unwrap_or("")
        .to_string();
    let url = mapping.url.as_deref().and_then(value_for).map(String::from);
    let folder = mapping
        .folder
        .as_deref()
        .and_then(value_for)
        .map(String::from);

    let totp = match mapping.totp_secret.as_deref().and_then(value_for) {
        None => None,
        Some(v) => {
            if v.starts_with("otpauth://") {
                // Delegate to the otpauth parser; pull the TOTP off the resulting login.
                let imported = super::otpauth::parse_otpauth_uri(v)?;
                if let crate::protocol::item::ItemContent::Login(l) = imported.content {
                    l.totp
                } else {
                    None
                }
            } else {
                let secret = v.replace([' ', '\t'], "").to_uppercase();
                if !super::otpauth::valid_base32(&secret) {
                    return Err(CryptoError::Import(
                        "csv totp secret must be base32 (RFC 4648)",
                    ));
                }
                Some(TotpConfig {
                    secret_base32: secret,
                    algorithm: TotpAlgorithm::Sha1,
                    digits: 6,
                    period_seconds: 30,
                })
            }
        }
    };

    let mut custom = Vec::new();
    let known: std::collections::HashSet<String> = [
        mapping.title.as_deref(),
        mapping.username.as_deref(),
        mapping.password.as_deref(),
        mapping.url.as_deref(),
        mapping.notes.as_deref(),
        mapping.totp_secret.as_deref(),
        mapping.folder.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::to_string)
    .chain(mapping.skip.iter().cloned())
    .map(|s| s.to_lowercase())
    .collect();

    for (i, header) in headers.iter().enumerate() {
        if known.contains(&header.to_lowercase()) {
            continue;
        }
        let Some(v) = row.get(i) else {
            continue;
        };
        if v.is_empty() {
            continue;
        }
        custom.push(super::custom_string_field(header.clone(), v.clone()));
    }

    let (notes_doc, notes_text) = crate::prose::from_plaintext(&notes);
    let login = LoginContent {
        username,
        password,
        urls: url
            .into_iter()
            .map(crate::protocol::item::LoginUrl::plain)
            .collect(),
        totp,
        notes: notes_doc,
        notes_text,
        custom_fields: custom,
        password_history: Vec::new(),
        raw_import: serde_json::Value::Null,
        ..Default::default()
    };

    let mut item = ImportedItem::new_login(title, login);
    item.source_collection = folder;
    Ok(Some(item))
}

/// RFC 4180-style CSV parser with quoted fields and escaped double-quotes.
/// Returns an iterator of rows where each row is a Vec<String> of fields.
fn parse_csv(input: &str) -> impl Iterator<Item = Vec<String>> + '_ {
    let mut chars = input.chars().peekable();
    std::iter::from_fn(move || {
        chars.peek()?;
        let mut row: Vec<String> = Vec::new();
        let mut field = String::new();
        let mut in_quotes = false;
        loop {
            match chars.next() {
                None => {
                    row.push(std::mem::take(&mut field));
                    return Some(row);
                }
                Some(c) => {
                    if in_quotes {
                        if c == '"' {
                            if chars.peek() == Some(&'"') {
                                chars.next();
                                field.push('"');
                            } else {
                                in_quotes = false;
                            }
                        } else {
                            field.push(c);
                        }
                    } else {
                        match c {
                            '"' if field.is_empty() => in_quotes = true,
                            ',' => row.push(std::mem::take(&mut field)),
                            '\r' => {
                                if chars.peek() == Some(&'\n') {
                                    chars.next();
                                }
                                row.push(std::mem::take(&mut field));
                                return Some(row);
                            }
                            '\n' => {
                                row.push(std::mem::take(&mut field));
                                return Some(row);
                            }
                            _ => field.push(c),
                        }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::ItemContent;

    #[test]
    fn parses_lastpass_export() {
        let csv = concat!(
            "name,url,username,password,extra,grouping,fav\n",
            "GitHub,https://github.com,alice,hunter2,sshkey backup,Work,1\n",
            "Bank,https://bank.example,alice@example.com,supersecret,,,0\n",
        );
        let (items, errors) = import_csv(csv, &CsvColumnMapping::lastpass());
        assert!(errors.is_empty());
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "GitHub");
        assert_eq!(items[0].source_collection.as_deref(), Some("Work"));
        if let ItemContent::Login(l) = &items[0].content {
            assert_eq!(l.username, "alice");
            assert_eq!(l.password, "hunter2");
            assert_eq!(l.urls.len(), 1);
            assert_eq!(l.urls[0].url, "https://github.com");
            assert_eq!(l.notes_text, "sshkey backup");
        }
    }

    #[test]
    fn autodetect_finds_common_columns() {
        let headers = ["Title", "URL", "Username", "Password", "OTP", "Custom1"];
        let m = CsvColumnMapping::autodetect(&headers);
        assert_eq!(m.title.as_deref(), Some("Title"));
        assert_eq!(m.username.as_deref(), Some("Username"));
        assert_eq!(m.password.as_deref(), Some("Password"));
        assert_eq!(m.url.as_deref(), Some("URL"));
        assert_eq!(m.totp_secret.as_deref(), Some("OTP"));
    }

    #[test]
    fn autodetect_prefers_username_over_email() {
        // Even when `email` appears first in the header row, `username` is the
        // canonical column and must win the auto-mapping.
        let headers = ["Email", "Username", "Password"];
        let m = CsvColumnMapping::autodetect(&headers);
        assert_eq!(m.username.as_deref(), Some("Username"));
    }

    #[test]
    fn autodetect_prefers_title_over_name() {
        let headers = ["Name", "Title", "Password"];
        let m = CsvColumnMapping::autodetect(&headers);
        assert_eq!(m.title.as_deref(), Some("Title"));
    }

    #[test]
    fn preserves_unknown_columns_as_custom_fields() {
        let csv = concat!(
            "Title,Username,Password,Extra Notes\n",
            "X,alice,hunter2,arbitrary metadata\n",
        );
        let m = CsvColumnMapping {
            title: Some("Title".into()),
            username: Some("Username".into()),
            password: Some("Password".into()),
            ..Default::default()
        };
        let (items, _) = import_csv(csv, &m);
        if let ItemContent::Login(l) = &items[0].content {
            assert_eq!(l.custom_fields.len(), 1);
            assert_eq!(l.custom_fields[0].name, "Extra Notes");
            assert_eq!(l.custom_fields[0].value, "arbitrary metadata");
        }
    }

    #[test]
    fn handles_quoted_fields_with_commas() {
        let csv = concat!("Title,Notes\n", "X,\"a, b, c\"\n");
        let m = CsvColumnMapping {
            title: Some("Title".into()),
            notes: Some("Notes".into()),
            ..Default::default()
        };
        let (items, _) = import_csv(csv, &m);
        if let ItemContent::Login(l) = &items[0].content {
            assert_eq!(l.notes_text, "a, b, c");
        }
    }

    #[test]
    fn parses_inline_otpauth() {
        let csv = concat!(
            "Title,OTP\n",
            "GitHub,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n",
        );
        let m = CsvColumnMapping {
            title: Some("Title".into()),
            totp_secret: Some("OTP".into()),
            ..Default::default()
        };
        let (items, _) = import_csv(csv, &m);
        if let ItemContent::Login(l) = &items[0].content {
            assert!(l.totp.is_some());
            assert_eq!(l.totp.as_ref().unwrap().secret_base32, "JBSWY3DPEHPK3PXP");
        }
    }

    #[test]
    fn rejects_invalid_raw_totp_secret() {
        let csv = "Title,OTP\nBad,ABC0123\n";
        let m = CsvColumnMapping {
            title: Some("Title".into()),
            totp_secret: Some("OTP".into()),
            ..Default::default()
        };
        let (items, errors) = import_csv(csv, &m);
        assert!(items.is_empty());
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, 2);
    }

    #[test]
    fn skips_blank_rows() {
        let csv = "Title\nA\n\n\nB\n";
        let m = CsvColumnMapping {
            title: Some("Title".into()),
            ..Default::default()
        };
        let (items, _) = import_csv(csv, &m);
        assert_eq!(items.len(), 2);
    }
}

//! KeePass XML importer.

use crate::error::{CryptoError, CryptoResult};
use crate::import::{ImportedItem, custom_concealed_field, custom_string_field};
use crate::protocol::item::{
    CustomField, LoginContent, LoginUrl, SecureNoteContent, TotpAlgorithm, TotpConfig,
};

use std::collections::BTreeSet;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde_json::json;
use thiserror::Error;

const MAX_KEEPASS_XML_BYTES: usize = 64 * 1024 * 1024;
const MAX_KEEPASS_ITEMS: usize = 50_000;
const MAX_KEEPASS_STRINGS_PER_ENTRY: usize = 512;
const MAX_KEEPASS_TEXT_BYTES: usize = 1024 * 1024;

const TITLE_KEY: &str = "Title";
const USERNAME_KEY: &str = "UserName";
const PASSWORD_KEY: &str = "Password";
const URL_KEY: &str = "URL";
const NOTES_KEY: &str = "Notes";
const OTP_KEY: &str = "otp";
const TOTP_SEED_KEY: &str = "TOTP Seed";
const TOTP_SETTINGS_KEY: &str = "TOTP Settings";
const TIMEOTP_SECRET_KEY: &str = "TimeOtp-Secret-Base32";
const TIMEOTP_ALGORITHM_KEY: &str = "TimeOtp-Algorithm";
const TIMEOTP_LENGTH_KEY: &str = "TimeOtp-Length";
const TIMEOTP_PERIOD_KEY: &str = "TimeOtp-Period";

#[derive(Debug, Error)]
pub enum KeePassImportError {
    #[error("export is not a KeePass XML database")]
    NotKeePassXml,
    #[error("KeePass XML parse failed")]
    Xml,
    #[error("KeePass XML exceeds importer safety limits")]
    SizeLimit,
}

impl From<KeePassImportError> for CryptoError {
    fn from(err: KeePassImportError) -> Self {
        match err {
            KeePassImportError::NotKeePassXml => CryptoError::Import("keepass xml database"),
            KeePassImportError::Xml => CryptoError::Import("keepass xml parse"),
            KeePassImportError::SizeLimit => CryptoError::Import("keepass xml size limit"),
        }
    }
}

/// Decode a KeePass XML database export into normalized item data.
pub fn import_keepass_xml(payload: &[u8]) -> CryptoResult<Vec<ImportedItem>> {
    if payload.len() > MAX_KEEPASS_XML_BYTES {
        return Err(KeePassImportError::SizeLimit.into());
    }
    let mut parser = KeePassXmlParser::new(payload);
    parser.parse().map_err(Into::into)
}

#[derive(Default)]
struct KeePassEntry {
    group_path: Vec<String>,
    tags: String,
    strings: Vec<KeePassString>,
}

#[derive(Default)]
struct KeePassString {
    key: Option<String>,
    value: String,
    encrypted: bool,
    protected: bool,
    saw_value: bool,
}

#[derive(Clone, Copy)]
enum TextTarget {
    GroupName(usize),
    EntryTags,
    StringKey,
    StringValue,
}

struct KeePassXmlParser<'a> {
    reader: Reader<&'a [u8]>,
    buf: Vec<u8>,
    saw_root: bool,
    inside_root: bool,
    finished_root: bool,
    group_stack: Vec<Option<String>>,
    current_entry: Option<KeePassEntry>,
    current_string: Option<KeePassString>,
    text_target: Option<TextTarget>,
    history_depth: usize,
    items: Vec<ImportedItem>,
}

impl<'a> KeePassXmlParser<'a> {
    fn new(payload: &'a [u8]) -> Self {
        let mut reader = Reader::from_reader(payload);
        reader.config_mut().trim_text(false);
        Self {
            reader,
            buf: Vec::new(),
            saw_root: false,
            inside_root: false,
            finished_root: false,
            group_stack: Vec::new(),
            current_entry: None,
            current_string: None,
            text_target: None,
            history_depth: 0,
            items: Vec::new(),
        }
    }

    fn parse(&mut self) -> Result<Vec<ImportedItem>, KeePassImportError> {
        loop {
            match self
                .reader
                .read_event_into(&mut self.buf)
                .map_err(|_| KeePassImportError::Xml)?
            {
                Event::Start(start) => {
                    let start = start.into_owned();
                    self.handle_start(&start)?;
                }
                Event::Empty(start) => {
                    let start = start.into_owned();
                    self.handle_empty(&start)?;
                }
                Event::End(end) => {
                    let name = end.name().as_ref().to_vec();
                    self.handle_end(&name)?;
                }
                Event::Text(text) => {
                    let decoded = text.decode().map_err(|_| KeePassImportError::Xml)?;
                    let decoded = decoded.into_owned();
                    self.append_text(&decoded)?;
                }
                Event::CData(text) => {
                    let decoded = text.decode().map_err(|_| KeePassImportError::Xml)?;
                    let decoded = decoded.into_owned();
                    self.append_text(&decoded)?;
                }
                Event::GeneralRef(entity) => {
                    let resolved = resolve_xml_entity(&entity)?;
                    self.append_text(&resolved)?;
                }
                Event::Eof => break,
                _ => {}
            }
            self.buf.clear();
        }
        if !self.saw_root {
            return Err(KeePassImportError::NotKeePassXml);
        }
        if self.inside_root
            || self.current_entry.is_some()
            || self.current_string.is_some()
            || self.history_depth > 0
        {
            return Err(KeePassImportError::Xml);
        }
        Ok(std::mem::take(&mut self.items))
    }

    fn handle_start(&mut self, start: &BytesStart<'_>) -> Result<(), KeePassImportError> {
        let name = start.name();
        let name = name.as_ref();
        if name == b"KeePassFile" {
            if self.saw_root {
                return Err(KeePassImportError::Xml);
            }
            self.saw_root = true;
            self.inside_root = true;
            return Ok(());
        }
        if !self.inside_root {
            return if self.finished_root {
                Err(KeePassImportError::Xml)
            } else {
                Err(KeePassImportError::NotKeePassXml)
            };
        }
        if self.history_depth > 0 {
            self.history_depth = self.history_depth.saturating_add(1);
            return Ok(());
        }
        match name {
            b"Group" if self.current_entry.is_none() => self.group_stack.push(None),
            b"Name" if self.current_entry.is_none() && !self.group_stack.is_empty() => {
                self.text_target = Some(TextTarget::GroupName(self.group_stack.len() - 1));
            }
            b"Entry" if self.current_entry.is_none() => {
                self.current_entry = Some(KeePassEntry {
                    group_path: self
                        .group_stack
                        .iter()
                        .filter_map(|name| name.as_ref())
                        .filter(|name| !name.is_empty())
                        .cloned()
                        .collect(),
                    ..KeePassEntry::default()
                });
            }
            b"History" if self.current_entry.is_some() => self.history_depth = 1,
            b"Tags" if self.current_entry.is_some() && self.current_string.is_none() => {
                self.text_target = Some(TextTarget::EntryTags);
            }
            b"String" if self.current_entry.is_some() && self.current_string.is_none() => {
                self.current_string = Some(KeePassString::default());
            }
            b"Key" if self.current_string.is_some() => {
                self.text_target = Some(TextTarget::StringKey);
            }
            b"Value" if self.current_string.is_some() => {
                if let Some(current) = self.current_string.as_mut() {
                    current.encrypted = attr_is_true(start, b"Protected");
                    current.protected =
                        current.encrypted || attr_is_true(start, b"ProtectInMemory");
                    current.saw_value = true;
                }
                self.text_target = Some(TextTarget::StringValue);
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_empty(&mut self, start: &BytesStart<'_>) -> Result<(), KeePassImportError> {
        let name = start.name();
        let name = name.as_ref();
        if name == b"KeePassFile" {
            if self.saw_root {
                return Err(KeePassImportError::Xml);
            }
            self.saw_root = true;
            self.finished_root = true;
            return Ok(());
        }
        if !self.inside_root {
            return if self.finished_root {
                Err(KeePassImportError::Xml)
            } else {
                Err(KeePassImportError::NotKeePassXml)
            };
        }
        if self.history_depth > 0 {
            return Ok(());
        }
        match name {
            b"Value" if self.current_string.is_some() => {
                if let Some(current) = self.current_string.as_mut() {
                    current.encrypted = attr_is_true(start, b"Protected");
                    current.protected =
                        current.encrypted || attr_is_true(start, b"ProtectInMemory");
                    current.saw_value = true;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_end(&mut self, name: &[u8]) -> Result<(), KeePassImportError> {
        if name == b"KeePassFile" {
            if !self.inside_root || self.history_depth > 0 {
                return Err(KeePassImportError::Xml);
            }
            self.inside_root = false;
            self.finished_root = true;
            self.group_stack.clear();
            self.text_target = None;
            return Ok(());
        }
        if !self.inside_root {
            return Err(KeePassImportError::Xml);
        }
        if self.history_depth > 0 {
            self.history_depth -= 1;
            return Ok(());
        }
        match name {
            b"Group" if self.current_entry.is_none() => {
                self.group_stack.pop();
            }
            b"Entry" => {
                if let Some(entry) = self.current_entry.take() {
                    if self.items.len() >= MAX_KEEPASS_ITEMS {
                        return Err(KeePassImportError::SizeLimit);
                    }
                    self.items.push(entry.into_item());
                }
            }
            b"String" => {
                if let (Some(entry), Some(string)) =
                    (self.current_entry.as_mut(), self.current_string.take())
                {
                    // `Protected` content is undecryptable outside the KDBX stream.
                    if string.encrypted && !string.value.is_empty() {
                        return Err(KeePassImportError::Xml);
                    }
                    if entry.strings.len() >= MAX_KEEPASS_STRINGS_PER_ENTRY {
                        return Err(KeePassImportError::SizeLimit);
                    }
                    if string.saw_value && string.key.as_deref().is_some_and(|key| !key.is_empty())
                    {
                        entry.strings.push(string);
                    }
                }
            }
            b"Name" | b"Tags" | b"Key" | b"Value" => self.text_target = None,
            _ => {}
        }
        Ok(())
    }

    fn append_text(&mut self, text: &str) -> Result<(), KeePassImportError> {
        if self.history_depth > 0 {
            return Ok(());
        }
        let Some(target) = self.text_target else {
            return Ok(());
        };
        match target {
            TextTarget::GroupName(index) => {
                let Some(slot) = self.group_stack.get_mut(index) else {
                    return Ok(());
                };
                let name = slot.get_or_insert_with(String::new);
                append_capped(name, text)?;
            }
            TextTarget::EntryTags => {
                if let Some(entry) = self.current_entry.as_mut() {
                    append_capped(&mut entry.tags, text)?;
                }
            }
            TextTarget::StringKey => {
                if let Some(current) = self.current_string.as_mut() {
                    let key = current.key.get_or_insert_with(String::new);
                    append_capped(key, text)?;
                }
            }
            TextTarget::StringValue => {
                if let Some(current) = self.current_string.as_mut() {
                    append_capped(&mut current.value, text)?;
                }
            }
        }
        Ok(())
    }
}

impl KeePassEntry {
    fn into_item(self) -> ImportedItem {
        let title = field_value(&self.strings, TITLE_KEY)
            .filter(|title| !title.is_empty())
            .unwrap_or("Untitled")
            .to_string();
        let notes = field_value(&self.strings, NOTES_KEY).unwrap_or_default();
        let (totp, consumed_totp_keys) = keepass_totp(&self.strings);
        let has_login_fields = field_value(&self.strings, USERNAME_KEY)
            .or_else(|| field_value(&self.strings, PASSWORD_KEY))
            .or_else(|| field_value(&self.strings, URL_KEY))
            .is_some_and(|value| !value.is_empty())
            || totp.is_some();
        let custom_fields = custom_fields(&self.strings, &consumed_totp_keys);
        let mut item = if has_login_fields {
            let (notes_doc, notes_text) = crate::prose::from_plaintext(notes);
            ImportedItem::new_login(
                title,
                LoginContent {
                    username: field_value(&self.strings, USERNAME_KEY)
                        .unwrap_or_default()
                        .to_string(),
                    password: field_value(&self.strings, PASSWORD_KEY)
                        .unwrap_or_default()
                        .to_string(),
                    urls: field_value(&self.strings, URL_KEY)
                        .filter(|url| !url.is_empty())
                        .map(|url| {
                            vec![LoginUrl {
                                url: url.to_string(),
                                match_type: None,
                            }]
                        })
                        .unwrap_or_default(),
                    totp,
                    notes: notes_doc,
                    notes_text,
                    custom_fields,
                    raw_import: keepass_raw_import(&self.group_path),
                    ..LoginContent::default()
                },
            )
        } else {
            let (body, body_text) = crate::prose::from_plaintext(notes);
            ImportedItem::new_secure_note(
                title,
                SecureNoteContent {
                    body,
                    body_text,
                    custom_fields,
                    raw_import: keepass_raw_import(&self.group_path),
                    ..SecureNoteContent::default()
                },
            )
        };
        item.tags = split_tags(&self.tags);
        item.source_collection = source_collection(&self.group_path);
        item
    }
}

fn append_capped(target: &mut String, value: &str) -> Result<(), KeePassImportError> {
    if target.len().saturating_add(value.len()) > MAX_KEEPASS_TEXT_BYTES {
        return Err(KeePassImportError::SizeLimit);
    }
    target.push_str(value);
    Ok(())
}

fn attr_is_true(start: &BytesStart<'_>, name: &[u8]) -> bool {
    start
        .attributes()
        .with_checks(false)
        .filter_map(Result::ok)
        .any(|attr| {
            attr.key.as_ref() == name
                && attr
                    .decoded_and_normalized_value(XmlVersion::Implicit1_0, start.decoder())
                    .ok()
                    .is_some_and(|value| value.eq_ignore_ascii_case("true") || value == "1")
        })
}

fn resolve_xml_entity(
    entity: &quick_xml::events::BytesRef<'_>,
) -> Result<String, KeePassImportError> {
    if let Some(ch) = entity
        .resolve_char_ref()
        .map_err(|_| KeePassImportError::Xml)?
    {
        return Ok(ch.to_string());
    }
    // DTD-defined entities are not part of KeePass XML exports.
    let name = entity.decode().map_err(|_| KeePassImportError::Xml)?;
    match name.as_ref() {
        "amp" => Ok("&".to_string()),
        "lt" => Ok("<".to_string()),
        "gt" => Ok(">".to_string()),
        "quot" => Ok("\"".to_string()),
        "apos" => Ok("'".to_string()),
        _ => Err(KeePassImportError::Xml),
    }
}

fn field_value<'a>(strings: &'a [KeePassString], key: &str) -> Option<&'a str> {
    strings
        .iter()
        .find(|field| field.key.as_deref() == Some(key))
        .map(|field| field.value.as_str())
}

fn custom_fields(
    strings: &[KeePassString],
    consumed_totp_keys: &BTreeSet<&'static str>,
) -> Vec<CustomField> {
    strings
        .iter()
        .filter_map(|field| {
            let key = field.key.as_deref()?;
            if keepass_reserved_key(key, consumed_totp_keys) || field.value.is_empty() {
                return None;
            }
            if field.protected || sensitive_key_name(key) {
                Some(custom_concealed_field(key, &field.value))
            } else {
                Some(custom_string_field(key, &field.value))
            }
        })
        .collect()
}

fn keepass_reserved_key(key: &str, consumed_totp_keys: &BTreeSet<&'static str>) -> bool {
    if totp_key(key) {
        return consumed_totp_keys.contains(key);
    }
    matches!(
        key,
        TITLE_KEY | USERNAME_KEY | PASSWORD_KEY | URL_KEY | NOTES_KEY
    )
}

fn totp_key(key: &str) -> bool {
    matches!(
        key,
        OTP_KEY
            | TOTP_SEED_KEY
            | TOTP_SETTINGS_KEY
            | TIMEOTP_SECRET_KEY
            | TIMEOTP_ALGORITHM_KEY
            | TIMEOTP_LENGTH_KEY
            | TIMEOTP_PERIOD_KEY
    )
}

fn sensitive_key_name(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "password",
        "passphrase",
        "secret",
        "token",
        "private",
        "seed",
        "pin",
        "cvv",
        "otp",
        "recovery",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn keepass_totp(strings: &[KeePassString]) -> (Option<TotpConfig>, BTreeSet<&'static str>) {
    if let Some(otp) = field_value(strings, OTP_KEY)
        && let Some(totp) = parse_keepass_totp_value(otp)
    {
        return (Some(totp), BTreeSet::from([OTP_KEY]));
    }
    if let Some(settings) = field_value(strings, TOTP_SETTINGS_KEY)
        && let Some(seed) = field_value(strings, TOTP_SEED_KEY)
        && let Some(totp) = parse_keepass_totp_value(settings)
            .or_else(|| legacy_totp(seed, settings))
            .or_else(|| raw_totp(seed, None, None, None))
    {
        return (
            Some(totp),
            BTreeSet::from([TOTP_SEED_KEY, TOTP_SETTINGS_KEY]),
        );
    }
    if let Some(secret) = field_value(strings, TIMEOTP_SECRET_KEY)
        && let Some(totp) = raw_totp(
            secret,
            field_value(strings, TIMEOTP_ALGORITHM_KEY),
            field_value(strings, TIMEOTP_LENGTH_KEY),
            field_value(strings, TIMEOTP_PERIOD_KEY),
        )
    {
        return (
            Some(totp),
            BTreeSet::from([
                TIMEOTP_SECRET_KEY,
                TIMEOTP_ALGORITHM_KEY,
                TIMEOTP_LENGTH_KEY,
                TIMEOTP_PERIOD_KEY,
            ]),
        );
    }
    (None, BTreeSet::new())
}

fn parse_keepass_totp_value(value: &str) -> Option<TotpConfig> {
    if value.starts_with("otpauth://") {
        return crate::import::otpauth::parse_otpauth_uri(value)
            .ok()
            .and_then(|item| match item.content {
                crate::protocol::item::ItemContent::Login(login) => login.totp,
                _ => None,
            });
    }
    if let Some(totp) = keeotp_totp(value) {
        return Some(totp);
    }
    raw_totp(value, None, None, None)
}

fn legacy_totp(secret: &str, settings: &str) -> Option<TotpConfig> {
    let mut parts = settings.split(';');
    let period = parts.next()?;
    let digits = parts.next()?;
    raw_totp(secret, None, Some(digits), Some(period))
}

fn keeotp_totp(settings: &str) -> Option<TotpConfig> {
    let key = query_value(settings, "key")?;
    raw_totp(
        &key,
        query_value(settings, "otpHashMode").as_deref(),
        query_value(settings, "size").as_deref(),
        query_value(settings, "step").as_deref(),
    )
}

fn query_value(input: &str, needle: &str) -> Option<String> {
    input.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        key.eq_ignore_ascii_case(needle)
            .then(|| percent_decode_query(value))
    })
}

fn percent_decode_query(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn raw_totp(
    secret: &str,
    algorithm: Option<&str>,
    digits: Option<&str>,
    period: Option<&str>,
) -> Option<TotpConfig> {
    let secret_base32 = secret.replace([' ', '\t'], "").to_uppercase();
    if !crate::import::otpauth::valid_base32(&secret_base32) {
        return None;
    }
    Some(TotpConfig {
        secret_base32,
        algorithm: match algorithm
            .unwrap_or("SHA1")
            .trim()
            .to_ascii_uppercase()
            .as_str()
        {
            "SHA256" => TotpAlgorithm::Sha256,
            "SHA512" => TotpAlgorithm::Sha512,
            _ => TotpAlgorithm::Sha1,
        },
        digits: digits
            .and_then(|d| d.parse::<u8>().ok())
            .map(|d| d.clamp(1, 10))
            .unwrap_or(6),
        period_seconds: period
            .and_then(|p| p.parse::<u32>().ok())
            .map(|p| p.clamp(1, 86_400))
            .unwrap_or(30),
    })
}

fn split_tags(tags: &str) -> Vec<String> {
    tags.split([',', ';', '\t'])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn source_collection(path: &[String]) -> Option<String> {
    let parts: Vec<&str> = path
        .iter()
        .map(String::as_str)
        .filter(|part| !part.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn keepass_raw_import(path: &[String]) -> serde_json::Value {
    match source_collection(path) {
        Some(path) => json!({ "keepass_group": path }),
        None => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::ItemContent;

    #[test]
    fn imports_keepass_login() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Group>
                            <Name>Email</Name>
                            <Entry>
                                <Tags>prod; shared</Tags>
                                <String><Key>Title</Key><Value>Mail</Value></String>
                                <String><Key>UserName</Key><Value>alice</Value></String>
                                <String><Key>Password</Key><Value ProtectInMemory="True">secret</Value></String>
                                <String><Key>URL</Key><Value>https://example.com</Value></String>
                                <String><Key>Notes</Key><Value>hello &amp; goodbye</Value></String>
                                <String><Key>Recovery token</Key><Value>abc123</Value></String>
                            </Entry>
                        </Group>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Mail");
        assert_eq!(items[0].source_collection.as_deref(), Some("Root/Email"));
        assert_eq!(items[0].tags, vec!["prod", "shared"]);
        match &items[0].content {
            ItemContent::Login(login) => {
                assert_eq!(login.username, "alice");
                assert_eq!(login.password, "secret");
                assert_eq!(login.urls[0].url, "https://example.com");
                assert_eq!(login.notes_text, "hello & goodbye");
                assert_eq!(login.custom_fields[0].name, "Recovery token");
                assert_eq!(
                    login.custom_fields[0].kind,
                    crate::protocol::item::CustomFieldKind::Concealed
                );
            }
            other => panic!("expected login, got {other:?}"),
        }
    }

    #[test]
    fn imports_keepass_secure_note() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Notes</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>Door code</Value></String>
                            <String><Key>Notes</Key><Value>1234</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        match &items[0].content {
            ItemContent::SecureNote(note) => assert_eq!(note.body_text, "1234"),
            other => panic!("expected secure note, got {other:?}"),
        }
    }

    #[test]
    fn imports_keepass_totp_fields() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>GitHub</Value></String>
                            <String><Key>UserName</Key><Value>alice</Value></String>
                            <String><Key>otp</Key><Value>otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&amp;issuer=GitHub&amp;period=45&amp;digits=8</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        match &items[0].content {
            ItemContent::Login(login) => {
                let totp = login.totp.as_ref().unwrap();
                assert_eq!(totp.secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.period_seconds, 45);
                assert_eq!(totp.digits, 8);
            }
            other => panic!("expected login, got {other:?}"),
        }
    }

    #[test]
    fn imports_legacy_totp_settings() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>GitHub</Value></String>
                            <String><Key>TOTP Seed</Key><Value>JBSWY3DPEHPK3PXP</Value></String>
                            <String><Key>TOTP Settings</Key><Value>45;8</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        match &items[0].content {
            ItemContent::Login(login) => {
                let totp = login.totp.as_ref().unwrap();
                assert_eq!(totp.secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.period_seconds, 45);
                assert_eq!(totp.digits, 8);
            }
            other => panic!("expected login, got {other:?}"),
        }
    }

    #[test]
    fn imports_keeotp_settings() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>GitHub</Value></String>
                            <String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP&amp;step=25&amp;size=8&amp;otpHashMode=Sha256</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        match &items[0].content {
            ItemContent::Login(login) => {
                let totp = login.totp.as_ref().unwrap();
                assert_eq!(totp.secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.algorithm, TotpAlgorithm::Sha256);
                assert_eq!(totp.period_seconds, 25);
                assert_eq!(totp.digits, 8);
            }
            other => panic!("expected login, got {other:?}"),
        }
    }

    #[test]
    fn preserves_unparsed_totp_fields() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>GitHub</Value></String>
                            <String><Key>otp</Key><Value>not-valid-base32</Value></String>
                            <String><Key>TOTP Seed</Key><Value>also-not-valid</Value></String>
                            <String><Key>TOTP Settings</Key><Value>45;8</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        match &items[0].content {
            ItemContent::SecureNote(note) => {
                assert_eq!(note.custom_fields.len(), 3);
                assert!(note.custom_fields.iter().all(|field| {
                    field.kind == crate::protocol::item::CustomFieldKind::Concealed
                }));
                assert!(
                    note.custom_fields
                        .iter()
                        .any(|field| field.name == "otp" && field.value == "not-valid-base32")
                );
            }
            other => panic!("expected secure note, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_keepass_xml() {
        let err = import_keepass_xml(b"<xml />").unwrap_err();
        assert!(matches!(err, CryptoError::Import("keepass xml database")));
    }

    #[test]
    fn rejects_entries_outside_root() {
        let xml = br#"
            <Entry>
                <String><Key>Title</Key><Value>Outside</Value></String>
                <String><Key>Password</Key><Value>secret</Value></String>
            </Entry>
            <KeePassFile />
        "#;
        let err = import_keepass_xml(xml).unwrap_err();
        assert!(matches!(err, CryptoError::Import("keepass xml database")));
    }

    #[test]
    fn skips_history_entries() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>Current</Value></String>
                            <String><Key>Password</Key><Value>current</Value></String>
                            <History>
                                <Entry>
                                    <String><Key>Title</Key><Value>Old</Value></String>
                                    <String><Key>Password</Key><Value>old</Value></String>
                                </Entry>
                            </History>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Current");
    }

    #[test]
    fn skips_history_text_under_active_field() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String>
                                <Key>Password</Key>
                                <Value>current<History><Entry><String><Key>Password</Key><Value>old</Value></String></Entry></History></Value>
                            </String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        match &items[0].content {
            ItemContent::Login(login) => assert_eq!(login.password, "current"),
            other => panic!("expected login, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_entity_without_expansion() {
        let xml = br#"<?xml version="1.0"?>
            <!DOCTYPE KeePassFile [ <!ENTITY boom "boom"> ]>
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>&boom;</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let err = import_keepass_xml(xml).unwrap_err();
        assert!(matches!(err, CryptoError::Import("keepass xml parse")));
    }

    #[test]
    fn resolves_numeric_character_references() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>&#65;&#x42;</Value></String>
                            <String><Key>Notes</Key><Value>line&#10;break</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let items = import_keepass_xml(xml).unwrap();
        assert_eq!(items[0].title, "AB");
        match &items[0].content {
            ItemContent::SecureNote(note) => assert_eq!(note.body_text, "line\nbreak"),
            other => panic!("expected secure note, got {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_input() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>Partial</Value></String>
        "#;
        let err = import_keepass_xml(xml).unwrap_err();
        assert!(matches!(err, CryptoError::Import("keepass xml parse")));
    }

    #[test]
    fn rejects_multiple_roots() {
        let xml = br#"<KeePassFile></KeePassFile><KeePassFile></KeePassFile>"#;
        let err = import_keepass_xml(xml).unwrap_err();
        assert!(matches!(err, CryptoError::Import("keepass xml parse")));
    }

    #[test]
    fn imports_empty_database() {
        let items = import_keepass_xml(b"<KeePassFile></KeePassFile>").unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn rejects_encrypted_protected_values() {
        let xml = br#"
            <KeePassFile>
                <Root>
                    <Group>
                        <Name>Root</Name>
                        <Entry>
                            <String><Key>Title</Key><Value>Current</Value></String>
                            <String><Key>Password</Key><Value Protected="True">c2VjcmV0</Value></String>
                        </Entry>
                    </Group>
                </Root>
            </KeePassFile>
        "#;
        let err = import_keepass_xml(xml).unwrap_err();
        assert!(matches!(err, CryptoError::Import("keepass xml parse")));
    }
}

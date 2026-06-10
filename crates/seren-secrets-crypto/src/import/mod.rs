//! Loss-preserving importers for foreign password-manager exports.
//!
//! Every importer returns a normalized stream of `ImportedItem`s. The caller
//! is responsible for choosing a destination vault,
//! generating a `VaultKey`, encrypting each item under it, and uploading the
//! ciphertext. The importers themselves never touch the network and never
//! produce ciphertext.

use crate::protocol::item::{
    ApiCredentialContent, BankAccountContent, CardContent, CryptoWalletContent, CustomField,
    CustomFieldKind, DatabaseContent, DocumentContent, DriverLicenseContent, IdentityContent,
    ItemContent, LoginContent, PassportContent, SecureNoteContent, ServerContent, SshKeyContent,
};

pub mod bitwarden;
pub mod csv_import;
pub mod keepass;
pub mod onepassword;
pub mod otpauth;

pub use bitwarden::{BitwardenImportError, import_bitwarden_encrypted_json, import_bitwarden_json};
pub use csv_import::{CsvColumnMapping, import_csv};
pub use keepass::{KeePassImportError, import_keepass_xml};
pub use onepassword::{ATTACHMENT_URI_SCHEME, OnePasswordImportError, import_1pux};
pub use otpauth::{parse_otpauth_uri, parse_otpauth_uris};

/// A typed item produced by an importer, ready to be encrypted by the caller.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedItem {
    pub title: String,
    pub content: ItemContent,
    pub favorite: bool,
    pub tags: Vec<String>,
    /// Optional source vault/folder hint. Caller may use this to bucket items
    /// into destination vaults; importers do not create vaults themselves.
    pub source_collection: Option<String>,
    /// Plaintext attachments surfaced by the importer. Each one carries the
    /// fresh UUID that any inline reference in `content` (custom field or
    /// ProseMirror node) uses via the `seren-secrets://attachment/<id>`
    /// URI scheme. The caller is responsible for encrypting each `data`
    /// buffer under the destination vault and uploading it.
    pub attachments: Vec<ImportedAttachment>,
}

/// Plaintext attachment bytes plus the identifier the inline reference uses
/// to find them. Importers generate a fresh UUID for each attachment so
/// the source's identifier (which may have been re-used across exports or
/// only meaningful inside the source app) never leaks into the destination
/// vault.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedAttachment {
    pub id: uuid::Uuid,
    pub filename: String,
    pub content_type: Option<String>,
    pub data: Vec<u8>,
}

// Imported items hold decrypted plaintext; Debug output must not include
// titles, tags, filenames, or attachment bytes.
impl std::fmt::Debug for ImportedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedItem")
            .field("title", &"<redacted>")
            .field("content", &self.content)
            .field("favorite", &self.favorite)
            .field("tags_len", &self.tags.len())
            .field("source_collection", &"<redacted>")
            .field("attachments", &self.attachments)
            .finish()
    }
}

impl std::fmt::Debug for ImportedAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedAttachment")
            .field("id", &self.id)
            .field("filename", &"<redacted>")
            .field("content_type", &self.content_type)
            .field("data_len", &self.data.len())
            .finish()
    }
}

impl ImportedItem {
    pub fn new_login(title: impl Into<String>, content: LoginContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Login(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_secure_note(title: impl Into<String>, content: SecureNoteContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::SecureNote(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_api_credential(title: impl Into<String>, content: ApiCredentialContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::ApiCredential(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_card(title: impl Into<String>, content: CardContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Card(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_identity(title: impl Into<String>, content: IdentityContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Identity(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_document(title: impl Into<String>, content: DocumentContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Document(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_ssh_key(title: impl Into<String>, content: SshKeyContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::SshKey(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_server(title: impl Into<String>, content: ServerContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Server(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_database(title: impl Into<String>, content: DatabaseContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Database(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_bank_account(title: impl Into<String>, content: BankAccountContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::BankAccount(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_passport(title: impl Into<String>, content: PassportContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::Passport(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_driver_license(title: impl Into<String>, content: DriverLicenseContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::DriverLicense(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }

    pub fn new_crypto_wallet(title: impl Into<String>, content: CryptoWalletContent) -> Self {
        Self {
            title: title.into(),
            content: ItemContent::CryptoWallet(content),
            favorite: false,
            tags: Vec::new(),
            source_collection: None,
            attachments: Vec::new(),
        }
    }
}

/// Helper available to every importer for keeping unmapped source fields.
pub(crate) fn custom_string_field(
    name: impl Into<String>,
    value: impl Into<String>,
) -> CustomField {
    CustomField {
        name: name.into(),
        kind: CustomFieldKind::String,
        value: value.into(),
        purpose: None,
        section_id: None,
    }
}

pub(crate) fn custom_concealed_field(
    name: impl Into<String>,
    value: impl Into<String>,
) -> CustomField {
    CustomField {
        name: name.into(),
        kind: CustomFieldKind::Concealed,
        value: value.into(),
        purpose: None,
        section_id: None,
    }
}

// Re-export the item content shapes so callers of the import module do not
// need to reach into protocol::item directly.
pub use crate::protocol::item::{
    ApiCredentialContent as ImportApiCredentialContent,
    ApiCredentialKind as ImportApiCredentialKind, LoginContent as ImportLoginContent,
    SecureNoteContent as ImportSecureNoteContent, TotpAlgorithm as ImportTotpAlgorithm,
    TotpConfig as ImportTotpConfig,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_imported_plaintext() {
        let mut item = ImportedItem::new_login(
            "Bank Login SECRET-TITLE",
            LoginContent {
                username: "alice@example.com".into(),
                password: "hunter2-SUPER-SECRET".into(),
                ..Default::default()
            },
        );
        item.tags = vec!["secret-tag".into()];
        item.source_collection = Some("Private Vault".into());
        item.attachments = vec![ImportedAttachment {
            id: uuid::Uuid::nil(),
            filename: "passport-scan.pdf".into(),
            content_type: Some("application/pdf".into()),
            data: b"ATTACHMENT-PLAINTEXT-BYTES".to_vec(),
        }];

        let rendered = format!("{item:?}");
        for secret in [
            "SECRET-TITLE",
            "hunter2-SUPER-SECRET",
            "secret-tag",
            "Private Vault",
            "passport-scan.pdf",
            "ATTACHMENT-PLAINTEXT-BYTES",
            // The byte values of the attachment plaintext, e.g. "65".
            "65, 84, 84",
        ] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked imported plaintext {secret}: {rendered}"
            );
        }
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("data_len"));
    }
}

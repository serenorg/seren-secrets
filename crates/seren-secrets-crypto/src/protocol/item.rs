//! Encrypt and decrypt item content under a vault key.
//!
//! Item content is a JSON document encrypted with XChaCha20-Poly1305.
//! Titles, tags, and other listing metadata are encrypted as separate blobs
//! using the same key but with distinct AAD so a listing endpoint can return
//! one without revealing the others.

use serde::{Deserialize, Serialize};
use seren_secrets_macros::RedactedDebug;

use crate::aead::{xchacha20_decrypt_with_aad, xchacha20_encrypt_with_aad};
use crate::error::CryptoResult;
use crate::keys::{ItemContentKey, VaultKey};
use crate::prose::ZeroizableJson;
use crate::zeroize_ext::ZeroizableBTreeMap;

/// What the client encrypts inside `content_ciphertext`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ItemContent {
    Login(LoginContent),
    SecureNote(SecureNoteContent),
    ApiCredential(ApiCredentialContent),
    /// Payment card (number / cardholder / expiry / CVV). Importers map
    /// 1Password 002 Credit Card and Bitwarden 003 Card into this.
    Card(CardContent),
    /// Personal-identity record: name, address, gov ids. Importers map
    /// 1Password 004 Identity and Bitwarden 004 Identity into this.
    Identity(IdentityContent),
    /// Standalone document/file metadata. The bytes live in
    /// `item_attachments`; this variant carries the surrounding context
    /// (filename, content-type, size, alt text). Useful for sharing a
    /// single file as its own item rather than a child of a Login.
    Document(DocumentContent),
    /// SSH keypair (private + public + fingerprint + passphrase).
    /// Importers map 1Password 114 SSH Key and Bitwarden's SSH key item
    /// type into this. Resolver field aliases: `private_key`,
    /// `public_key`, `passphrase`.
    SshKey(SshKeyContent),
    /// Remote server (SSH/RDP/etc.). Importers map 1Password 110 Server.
    Server(ServerContent),
    /// Database connection. Importers map 1Password 102 Database.
    Database(DatabaseContent),
    /// Bank account: routing/account numbers, IBAN/SWIFT, PIN.
    /// Importers map 1Password 101 Bank Account here.
    BankAccount(BankAccountContent),
    /// Travel passport. Importers map 1Password 106 Passport here.
    Passport(PassportContent),
    /// Driver licence. Importers map 1Password 103 Driver Licence here.
    DriverLicense(DriverLicenseContent),
    /// Crypto wallet: seed phrase, derivation path, multiple addresses.
    /// Importers map 1Password 115 Crypto Wallet here.
    CryptoWallet(CryptoWalletContent),
}

impl std::fmt::Debug for ItemContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            ItemContent::Login(_) => "Login",
            ItemContent::SecureNote(_) => "SecureNote",
            ItemContent::ApiCredential(_) => "ApiCredential",
            ItemContent::Card(_) => "Card",
            ItemContent::Identity(_) => "Identity",
            ItemContent::Document(_) => "Document",
            ItemContent::SshKey(_) => "SshKey",
            ItemContent::Server(_) => "Server",
            ItemContent::Database(_) => "Database",
            ItemContent::BankAccount(_) => "BankAccount",
            ItemContent::Passport(_) => "Passport",
            ItemContent::DriverLicense(_) => "DriverLicense",
            ItemContent::CryptoWallet(_) => "CryptoWallet",
        };
        write!(f, "ItemContent::{variant}(<redacted>)")
    }
}

/// Decrypted item content that scrubs its plaintext on drop.
///
/// Call `into_inner` only when transferring the full plaintext item to an API
/// whose caller owns the zeroization responsibility.
pub struct DecryptedItemContent {
    content: Option<ItemContent>,
}

impl DecryptedItemContent {
    fn new(content: ItemContent) -> Self {
        Self {
            content: Some(content),
        }
    }

    pub fn as_content(&self) -> &ItemContent {
        self.content
            .as_ref()
            .expect("decrypted item content already consumed")
    }

    pub fn as_mut_content(&mut self) -> &mut ItemContent {
        self.content
            .as_mut()
            .expect("decrypted item content already consumed")
    }

    pub fn into_inner(mut self) -> ItemContent {
        self.content
            .take()
            .expect("decrypted item content already consumed")
    }
}

impl AsRef<ItemContent> for DecryptedItemContent {
    fn as_ref(&self) -> &ItemContent {
        self.as_content()
    }
}

impl AsMut<ItemContent> for DecryptedItemContent {
    fn as_mut(&mut self) -> &mut ItemContent {
        self.as_mut_content()
    }
}

impl std::ops::Deref for DecryptedItemContent {
    type Target = ItemContent;

    fn deref(&self) -> &Self::Target {
        self.as_content()
    }
}

impl std::ops::DerefMut for DecryptedItemContent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_content()
    }
}

impl std::fmt::Debug for DecryptedItemContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DecryptedItemContent")
            .field(&"<redacted>")
            .finish()
    }
}

impl PartialEq<ItemContent> for DecryptedItemContent {
    fn eq(&self, other: &ItemContent) -> bool {
        self.as_content() == other
    }
}

impl PartialEq<DecryptedItemContent> for ItemContent {
    fn eq(&self, other: &DecryptedItemContent) -> bool {
        self == other.as_content()
    }
}

impl ::zeroize::Zeroize for DecryptedItemContent {
    fn zeroize(&mut self) {
        if let Some(content) = self.content.as_mut() {
            ::zeroize::Zeroize::zeroize(content);
        }
    }
}

impl Drop for DecryptedItemContent {
    fn drop(&mut self) {
        ::zeroize::Zeroize::zeroize(self);
    }
}

/// Named grouping for `CustomField` entries. Mirrors 1Password's section
/// model so importers can preserve the source-app layout and clients can
/// render fields in the user's chosen order. The id is client-generated and
/// stable across edits so a field's `section_id` keeps pointing at the same
/// section after renames.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct Section {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
}

/// Email address with an optional label ("Work", "Personal"). Replaces the
/// single `email: String` on Identity so an imported 1Password Identity
/// with multiple emails round-trips intact.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct EmailEntry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default)]
    pub value: String,
}

/// Phone number with an optional label. Same shape and rationale as
/// `EmailEntry`.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct PhoneEntry {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default)]
    pub value: String,
}

/// Password generator parameters captured at generation time. Persisted on
/// `LoginContent` so the user can regenerate with the same recipe later.
/// Optional; absent on imported items and on logins typed in by hand.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct GeneratorRecipe {
    #[serde(default)]
    pub length: u32,
    #[serde(default)]
    pub include_letters: bool,
    #[serde(default)]
    pub include_numbers: bool,
    #[serde(default)]
    pub include_symbols: bool,
    /// Characters the user explicitly excluded (often `lO01I` to avoid
    /// visually confusable glyphs). Empty when no exclusions apply.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub excluded_characters: String,
    /// When set, generation chose words rather than character classes. The
    /// `length` field then describes the word count; `delimiter`, `case`
    /// shape the assembled passphrase.
    #[serde(default)]
    pub words_mode: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub word_delimiter: String,
}

/// Stored FIDO2 / WebAuthn credential. Reserved for the upcoming
/// passkey-in-vault feature. Today the field is a passthrough: clients
/// that don't understand it preserve the bytes round-trip via the
/// existing JSON serde. The server never inspects it; the entire item
/// body is sealed under the per-item content key.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct Fido2Credential {
    /// Base64url credential id assigned by the relying party.
    pub credential_id: String,
    /// Base64url user handle the RP assigned at registration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_handle: String,
    /// Relying-party identifier (the eTLD+1 the credential is scoped to).
    pub rp_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rp_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_display_name: String,
    /// Algorithm identifier from the COSE registry. ES256 (-7) is the
    /// universal default; clients write the algorithm name (e.g.
    /// `"ES256"`) for human readability rather than the COSE integer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub algorithm: String,
    /// PEM- or base64-encoded private key material, sealed under the
    /// item content key by the time it reaches storage.
    pub private_key: String,
    /// Signature counter; clients increment on each assertion.
    #[serde(default)]
    pub counter: u32,
    /// True when the RP requested a discoverable / resident key.
    #[serde(default)]
    pub discoverable: bool,
    /// RFC3339 timestamp of registration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
}

#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct LoginContent {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// URLs the login is associated with, with an optional `match_type`
    /// hint for autofill clients.
    #[serde(default)]
    pub urls: Vec<LoginUrl>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
    /// ProseMirror document. The newtype gates construction so explicit
    /// `null`, missing, or non-doc-shaped input collapses to an empty
    /// document. See [`crate::prose`] for helpers and the
    /// `seren-secrets://attachment/` scheme.
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    /// Plain-text projection of `notes` for list views and search indexing.
    /// Derived by clients on every write; on read, `notes` is canonical.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Per-password rotation log. Each entry is a previous password the
    /// user retired, with the timestamp it was changed. Clients append
    /// on every password change and drop the oldest when the log
    /// exceeds [`MAX_PASSWORD_HISTORY`]; the server stores whatever the
    /// client sends without enforcing the cap so an importer carrying a
    /// longer history from a foreign source can land it intact. Useful
    /// for "what was my previous password" UIs without round-tripping
    /// ciphertext through `/items/{id}/history`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Parameters used the last time the client generated this password.
    /// Optional; absent when the password was typed in or imported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator_recipe: Option<GeneratorRecipe>,
    /// Autofill hint. None means "use the caller's default."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofill_on_page_load: Option<bool>,
    /// FIDO2 / WebAuthn credentials stored against this login. Empty
    /// today; reserved for the upcoming passkey-in-vault feature. Clients
    /// that don't model passkeys preserve the array on round-trip.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fido2_credentials: Vec<Fido2Credential>,
    /// Named groupings the user assigned to `custom_fields`. Empty when
    /// the user hasn't introduced sections; importers populate from the
    /// source app's section layout.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    /// Loss-preserving bucket: original importer fields we did not normalize.
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Recommended cap on `LoginContent::password_history` length. Clients
/// trim the oldest entries on append to stay under this bound. Not
/// server-enforced because importers may carry longer histories from
/// foreign sources.
pub const MAX_PASSWORD_HISTORY: usize = 16;

/// One retired password plus when the rotation happened. The timestamp
/// is RFC3339 UTC; clients render the relative form ("2 months ago")
/// from there.
#[derive(Clone, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct PasswordHistoryEntry {
    pub password: String,
    /// RFC3339 UTC timestamp recording when this password stopped being
    /// the active one.
    pub changed_at: String,
}

/// One URL associated with a `LoginContent`, with an optional match-type
/// hint that a future autofill client can use to scope where the
/// credential is offered. The match types mirror Bitwarden's URI match
/// strategies and 1Password's `autofillBehavior` so importers can carry
/// the source's intent through end-to-end.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct LoginUrl {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<UrlMatchType>,
}

impl LoginUrl {
    /// Bare URL with no match-type hint. Most importers and the existing
    /// codebase construct LoginUrl this way.
    pub fn plain(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            match_type: None,
        }
    }
}

impl From<&str> for LoginUrl {
    fn from(s: &str) -> Self {
        Self::plain(s)
    }
}

impl From<String> for LoginUrl {
    fn from(s: String) -> Self {
        Self::plain(s)
    }
}

/// How a client should decide whether a stored URL applies to a page the
/// user is on. The variants follow the established password-manager
/// vocabulary so an autofill UI does not need a translation table.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMatchType {
    /// Match only if the full URL (scheme + host + path + query)
    /// matches exactly.
    Exact,
    /// Match if the stored URL is a prefix of the candidate URL.
    StartsWith,
    /// Match if the candidate URL's host equals the stored URL's host
    /// (case-insensitive). The default for most autofill flows.
    Host,
    /// Never autofill on a page matching this URL even if another entry
    /// would otherwise. Used to opt a credential out of phishing-bait
    /// domains.
    Never,
    /// Regex match against the candidate URL. Power-user only.
    Regex,
}

#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct SecureNoteContent {
    /// ProseMirror document. The newtype gates construction so explicit
    /// `null`, missing, or non-doc-shaped input collapses to an empty
    /// document. See [`crate::prose`] for helpers and the
    /// `seren-secrets://attachment/` scheme.
    #[serde(default)]
    pub body: crate::prose::ProseDoc,
    /// Plain-text projection of `body` for list views and search indexing.
    /// Derived by clients on every write; on read, `body` is canonical.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCredentialKind {
    #[default]
    ApiKey,
    Oauth2Token,
    Basic,
    Mtls,
    AwsSigV4,
    GcpServiceAccount,
}

#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct ApiCredentialContent {
    // The outer `ItemContent` enum is internally tagged on `kind`, so the
    // inner credential-kind field has to land on the wire under a different
    // name. Without the rename, both fields serialize as `"kind"` and
    // deserialization can't recover the variant tag at all (the second
    // value wins and matches no `ItemContent` variant).
    #[serde(rename = "credential_kind", default)]
    pub kind: ApiCredentialKind,
    #[serde(default)]
    pub primary_value: String,
    #[serde(default)]
    pub secondary_value: String,
    #[serde(default)]
    pub headers: ZeroizableBTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<RotationPolicy>,
    /// ProseMirror document. The newtype gates construction so explicit
    /// `null`, missing, or non-doc-shaped input collapses to an empty
    /// document. See [`crate::prose`] for helpers and the
    /// `seren-secrets://attachment/` scheme.
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    /// Plain-text projection of `notes` for list views and search indexing.
    /// Derived by clients on every write; on read, `notes` is canonical.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Personal-identity record. Every field is optional so a partial import
/// (only first name + email, for example) stays a valid Identity rather
/// than forcing the importer to default missing strings to empty.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct IdentityContent {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub first_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub middle_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_name: String,
    /// Online handle distinct from email (Twitter, GitHub, etc.). 1Password
    /// and Bitwarden both surface this separately from email; we mirror.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// Employer.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub company: String,
    /// Job title.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub job_title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gender: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
    /// Email addresses with optional labels. Multiple entries supported
    /// for parity with 1Password / Bitwarden which both let the user
    /// label work / personal / etc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<EmailEntry>,
    /// Phone numbers with optional labels (work / mobile / fax / ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phones: Vec<PhoneEntry>,
    /// One or more postal addresses. Each address can carry an optional
    /// label via the section model; the address struct itself stays
    /// uniform across kinds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<PostalAddress>,
    /// Government identifiers: SSN, national id, residence permit number.
    /// First-class Passport and DriverLicense kinds exist for those two
    /// documents; `government_ids` is the catch-all for everything else.
    #[serde(default)]
    pub government_ids: Vec<GovernmentId>,
    /// ProseMirror document. See `crate::prose`.
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct PostalAddress {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub street: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub postal_code: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
}

#[derive(Clone, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct GovernmentId {
    /// Free-form label such as `"US passport"` or `"Driver license (CA)"`.
    pub label: String,
    pub number: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer: String,
}

/// Payment card. Field names match the well-known ISO/IEC 7813 vocabulary.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct CardContent {
    /// Name as printed on the card.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cardholder_name: String,
    /// Primary Account Number. Stored as a plain string; clients render
    /// this with masking. Server never decrypts.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub number: String,
    /// Visa, MasterCard, Amex, etc. Free-form to avoid an enum churn on
    /// new card networks.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub brand: String,
    /// MM/YY or MM/YYYY; clients normalize for display.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expiry: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cvv: String,
    /// PIN for in-person use.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pin: String,
    /// Optional billing address override (defaults to the cardholder's
    /// Identity record on the client side; not enforced here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_address: Option<PostalAddress>,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// SSH keypair. The resolver answers field aliases `private_key`,
/// `public_key`, and `passphrase` by reading the respective fields here.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct SshKeyContent {
    /// PEM-encoded private key. The client decides which format
    /// (OpenSSH, PKCS#8, RFC 4716) and the server never inspects.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    /// `ssh-rsa AAAA...`, `ssh-ed25519 AAAA...`, etc.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_key: String,
    /// Optional passphrase protecting the private key when stored on disk.
    /// Stored alongside the key so an agent can unwrap a passphrase-bound
    /// key in one resolve call.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub passphrase: String,
    /// `ssh-keygen -l` style fingerprint, e.g. `SHA256:abc...`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// Free-form key type label: `ed25519`, `rsa-4096`, `ecdsa-p256`, ...
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_type: String,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Standalone document / file. The bytes live in `item_attachments`;
/// this variant carries the metadata. Pairs naturally with the
/// `seren-secrets://attachment/<uuid>` URI scheme - a Document item
/// typically references exactly one attachment.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct DocumentContent {
    /// User-facing filename. Clients display this; the actual stored
    /// filename in `item_attachments` may have been sanitized.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub filename: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// Plaintext byte length. Used for display only; the server stores
    /// only ciphertext, so this is a client-supplied hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Accessibility label (alt text).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alt_text: String,
    /// Attachment reference: typically a `seren-secrets://attachment/<uuid>`
    /// URI pointing at the bytes in `item_attachments`. Optional so a
    /// pure-metadata Document (e.g. "passport on file in the safe") is
    /// representable without an attachment.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attachment_uri: String,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Bank account: routing/account numbers, IBAN/SWIFT, branch, PIN. Maps to
/// 1Password's category 101 (Bank Account) and Bitwarden's identity-style
/// bank-account fields. Every field is optional so partial imports stay
/// representable.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct BankAccountContent {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bank_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account_holder: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account_number: String,
    /// US ABA / RTN. Free-form string so non-US routing variants stay
    /// readable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub routing_number: String,
    /// Checking, savings, money_market, certificate_of_deposit, ... Free-
    /// form because the source apps don't agree on an enum either.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account_type: String,
    /// International Bank Account Number.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub iban: String,
    /// BIC / SWIFT code.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub swift: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub branch: String,
    /// PIN for ATM / telephone banking.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pin: String,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Travel passport. Maps to 1Password's category 106 (Passport).
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct PassportContent {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub number: String,
    /// ICAO 9303 document type code, typically `P` for ordinary passport.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub passport_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub full_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub surname: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub given_names: String,
    /// ISO 3166-1 alpha-3 country code or free-form country name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nationality: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub place_of_birth: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gender: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuing_country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuing_authority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<String>,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Driver licence. Maps to 1Password's category 103 (Driver Licence).
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct DriverLicenseContent {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub number: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub full_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gender: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<PostalAddress>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    /// Licence class, e.g. `C`, `Class 5`, `LGV`. Free-form because each
    /// jurisdiction uses its own letters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub license_class: String,
    /// Endorsements and restrictions, e.g. `Corrective lenses`, `Motorcycle`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub conditions: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_on: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<String>,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Crypto wallet. Maps to 1Password's category 115 (Crypto Wallet). Stores
/// the seed phrase and/or private key plus an optional list of derived
/// addresses with labels.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct CryptoWalletContent {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub wallet_name: String,
    /// Network identifier: `Ethereum`, `Bitcoin`, `Solana`, ... Free-form.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    /// BIP39 mnemonic (typically 12 / 18 / 24 words, space-separated).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seed_phrase: String,
    /// Raw private key (hex, base58, WIF). Optional when only the seed
    /// phrase is stored.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    /// Wallet unlock password (distinct from any derived passphrase).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// BIP32 / SLIP10 derivation path, e.g. `m/44'/60'/0'/0/0`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub derivation_path: String,
    /// One or more derived addresses with optional labels (`Receiving`,
    /// `Cold storage`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<WalletAddress>,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct WalletAddress {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    #[serde(default)]
    pub address: String,
}

/// Remote server. Maps to 1Password's category 110 (Server). Covers SSH,
/// RDP, VNC, HTTP/S admin endpoints, etc. Pair with an SshKey item via
/// `ssh_key_reference` (a `seren-secrets://` URI) when the server is
/// accessed by key rather than password.
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct ServerContent {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// `seren-secrets://<vault>/<item>` URI pointing at the SSH key item
    /// used for this server. Optional; password-only servers leave it
    /// empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ssh_key_reference: String,
    /// 1Password Server records also accept an admin console URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub admin_console_url: String,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

/// Database connection. Maps to 1Password's category 102 (Database).
#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct DatabaseContent {
    /// Engine family: `postgres`, `mysql`, `mongo`, `mssql`, `redis`, ...
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub database_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub database_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password: String,
    /// Oracle System Identifier (SID) for Oracle deployments.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    /// Default schema or namespace inside the database.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema: String,
    #[serde(default)]
    pub notes: crate::prose::ProseDoc,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes_text: String,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub raw_import: ZeroizableJson,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPolicyKind {
    Manual,
    Scheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct RotationPolicy {
    pub policy: RotationPolicyKind,
    /// RFC3339 timestamp for the next rotation, if scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_rotation_at: Option<String>,
}

#[derive(Clone, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
pub struct TotpConfig {
    pub secret_base32: String,
    #[serde(default = "TotpConfig::default_algo")]
    pub algorithm: TotpAlgorithm,
    #[serde(default = "TotpConfig::default_digits")]
    pub digits: u8,
    #[serde(default = "TotpConfig::default_period")]
    pub period_seconds: u32,
}

impl TotpConfig {
    fn default_algo() -> TotpAlgorithm {
        TotpAlgorithm::Sha1
    }
    fn default_digits() -> u8 {
        6
    }
    fn default_period() -> u32 {
        30
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(
    Clone, Default, RedactedDebug, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize,
)]
pub struct CustomField {
    pub name: String,
    pub kind: CustomFieldKind,
    pub value: String,
    /// Optional semantic role of this field. When set, the
    /// agent-secrets resolver can answer a generic
    /// `seren-secrets://v/i/password` reference by picking the first
    /// field whose purpose matches, regardless of what the user named
    /// the field. Useful for ApiCredential items whose custom_fields
    /// are the only structure, and for surfacing imported fields whose
    /// source format already carried a purpose hint (e.g. 1Password's
    /// `purpose=PASSWORD`).
    ///
    /// Resolver precedence: name match (case-insensitive) wins over
    /// purpose match. A field named "Password" with
    /// `purpose=Username` will resolve to the requested `password`
    /// alias because the name matched first. Purpose is the fallback,
    /// used only when no field name matches the requested alias. This
    /// preserves the existing contract that the user-visible field
    /// name is the authoritative key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<FieldPurpose>,
    /// Optional pointer to a `Section.id` on the same item. None means
    /// "default / unsectioned". Renaming a section by editing its title
    /// keeps fields attached because the id is stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldKind {
    #[default]
    String,
    Concealed,
    Url,
    Email,
    Date,
}

/// Semantic role hint for a CustomField. Mirrors 1Password's `purpose`
/// concept so a resolver can answer "the password" without knowing the
/// item's schema. Adding a variant is forward-compatible; the resolver's
/// alias dispatch ignores unrecognized purposes the same way it ignores
/// custom fields with no purpose set.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, zeroize::Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPurpose {
    Username,
    Password,
    Notes,
    Otp,
    PrivateKey,
    PublicKey,
    CardNumber,
    Cvv,
    Pin,
}

/// AAD used when sealing item bodies. Binds the ciphertext to the item id.
fn body_aad(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + 6);
    aad.extend_from_slice(b"body:");
    aad.extend_from_slice(item_id);
    aad
}

/// AAD used when sealing titles. Binds the ciphertext to the item id.
fn title_aad(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + 7);
    aad.extend_from_slice(b"title:");
    aad.extend_from_slice(item_id);
    aad
}

fn tags_aad(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + 6);
    aad.extend_from_slice(b"tags:");
    aad.extend_from_slice(item_id);
    aad
}

fn metadata_aad(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + 14);
    aad.extend_from_slice(b"item-metadata:");
    aad.extend_from_slice(item_id);
    aad
}

fn last_used_aad(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + 11);
    aad.extend_from_slice(b"last_used:");
    aad.extend_from_slice(item_id);
    aad
}

// ---------------------------------------------------------------------------
// Per-item content keys
// ---------------------------------------------------------------------------
//
// Each item carries:
//   - `content_key_wrap`: the content key sealed under the vault key
//                         (so every vault member can derive it on read)
//   - body ciphertext sealed under that content key
//
// To share or approve a single item, hand out the content key alone -- the
// recipient can decrypt that item's body without ever seeing the vault key.
// Titles continue to use the vault key directly because every vault member
// must be able to list.

/// AAD binding for the content-key wrap. Distinct prefix so a stray wrap
/// can never be confused with a body or title ciphertext.
fn content_key_wrap_aad(item_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + 18);
    aad.extend_from_slice(b"item-content-key:");
    aad.extend_from_slice(item_id);
    aad
}

/// Mint a fresh per-item content key. Random 32 bytes; the same key gets
/// reused for the lifetime of the item (rotated only by a deliberate
/// re-wrap step).
pub fn generate_item_content_key() -> ItemContentKey {
    ItemContentKey::random()
}

/// Seal the content key under the vault key with item-id AAD.
pub fn wrap_item_content_key(
    vault_key: &VaultKey,
    item_id: &[u8],
    content_key: &ItemContentKey,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        content_key.as_bytes(),
        &content_key_wrap_aad(item_id),
    )
}

/// Recover the content key from the vault-key-sealed wrap. Returns
/// `InvalidCiphertext` if the unwrapped bytes are not exactly 32 bytes.
pub fn unwrap_item_content_key(
    vault_key: &VaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> CryptoResult<ItemContentKey> {
    // Zeroizing: this buffer is the raw content key; wipe it once copied
    // into the self-zeroizing newtype.
    let pt = zeroize::Zeroizing::new(xchacha20_decrypt_with_aad(
        vault_key.as_bytes(),
        blob,
        &content_key_wrap_aad(item_id),
    )?);
    let arr: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| crate::error::CryptoError::InvalidCiphertext)?;
    Ok(ItemContentKey::from_bytes(arr))
}

/// Encrypt an item body under its per-item content key. The AAD layout
/// matches `encrypt_item`, so the body envelope shape is stable.
pub fn encrypt_item_with_content_key(
    content_key: &ItemContentKey,
    item_id: &[u8],
    content: &ItemContent,
) -> CryptoResult<Vec<u8>> {
    let json = zeroize::Zeroizing::new(
        serde_json::to_vec(content)
            .map_err(|_| crate::error::CryptoError::Export("item content json"))?,
    );
    Ok(xchacha20_encrypt_with_aad(
        content_key.as_bytes(),
        &json,
        &body_aad(item_id),
    ))
}

/// Decrypt an item body under its per-item content key.
///
/// The returned guard zeroizes the plaintext item on drop. Call `into_inner`
/// only when deliberately transferring plaintext ownership to another API.
pub fn decrypt_item_with_content_key(
    content_key: &ItemContentKey,
    item_id: &[u8],
    blob: &[u8],
) -> CryptoResult<DecryptedItemContent> {
    let pt = zeroize::Zeroizing::new(xchacha20_decrypt_with_aad(
        content_key.as_bytes(),
        blob,
        &body_aad(item_id),
    )?);
    serde_json::from_slice(&pt)
        .map(DecryptedItemContent::new)
        .map_err(|_| crate::error::CryptoError::Import("item content json"))
}

pub fn encrypt_title(vault_key: &VaultKey, item_id: &[u8], title: &str) -> Vec<u8> {
    xchacha20_encrypt_with_aad(vault_key.as_bytes(), title.as_bytes(), &title_aad(item_id))
}

pub fn decrypt_title(vault_key: &VaultKey, item_id: &[u8], blob: &[u8]) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(vault_key.as_bytes(), blob, &title_aad(item_id))?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_tags(
    vault_key: &VaultKey,
    item_id: &[u8],
    tags: &[String],
) -> CryptoResult<Vec<u8>> {
    let json =
        serde_json::to_vec(tags).map_err(|_| crate::error::CryptoError::Export("tags json"))?;
    Ok(xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        &json,
        &tags_aad(item_id),
    ))
}

pub fn decrypt_tags(
    vault_key: &VaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> CryptoResult<Vec<String>> {
    let pt = xchacha20_decrypt_with_aad(vault_key.as_bytes(), blob, &tags_aad(item_id))?;
    serde_json::from_slice(&pt).map_err(|_| crate::error::CryptoError::Import("tags json"))
}

/// Encrypt list metadata for an item under the vault key.
///
/// The server stores and returns this opaque blob but cannot inspect it.
/// Clients put fields such as item kind, favorite, reprompt, and display
/// sensitivity in the JSON. Server-enforced approval policy still uses its
/// own minimal plaintext policy bit.
pub fn encrypt_metadata_json(vault_key: &VaultKey, item_id: &[u8], json: &str) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        json.as_bytes(),
        &metadata_aad(item_id),
    )
}

pub fn decrypt_metadata_json(
    vault_key: &VaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(vault_key.as_bytes(), blob, &metadata_aad(item_id))?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_last_used(vault_key: &VaultKey, item_id: &[u8], rfc3339: &str) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        rfc3339.as_bytes(),
        &last_used_aad(item_id),
    )
}

pub fn decrypt_last_used(
    vault_key: &VaultKey,
    item_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(vault_key.as_bytes(), blob, &last_used_aad(item_id))?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect1(prefix: &[u8], id: &[u8]) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(id);
        v
    }

    /// Frozen AAD layout. A silent prefix rename in any per-item slot is the
    /// cross-implementation canary; the exact bytes are pinned with
    /// independent literals, so changing a builder without updating the client
    /// and agent in lockstep fails here.
    #[test]
    fn item_aad_layout_is_frozen() {
        let id = [0xABu8; 16];
        assert_eq!(body_aad(&id), expect1(b"body:", &id));
        assert_eq!(title_aad(&id), expect1(b"title:", &id));
        assert_eq!(tags_aad(&id), expect1(b"tags:", &id));
        assert_eq!(metadata_aad(&id), expect1(b"item-metadata:", &id));
        assert_eq!(last_used_aad(&id), expect1(b"last_used:", &id));
        assert_eq!(
            content_key_wrap_aad(&id),
            expect1(b"item-content-key:", &id)
        );
    }

    #[test]
    fn debug_redacts_secret_item_body() {
        let content = ItemContent::Login(LoginContent {
            password: "hunter2-SUPER-SECRET".into(),
            ..Default::default()
        });
        let rendered = format!("{content:?}");
        assert!(
            !rendered.contains("hunter2-SUPER-SECRET"),
            "Debug leaked a secret field: {rendered}"
        );
        assert!(rendered.contains("redacted"));
        assert!(rendered.contains("Login"));
    }

    #[test]
    fn debug_redacts_secret_content_subtypes() {
        let login = LoginContent {
            username: "alice@example.com".into(),
            password: "hunter2-SUPER-SECRET".into(),
            totp: Some(TotpConfig {
                secret_base32: "JBSWY3DPEHPK3PXP".into(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period_seconds: 30,
            }),
            custom_fields: vec![CustomField {
                name: "api token".into(),
                kind: CustomFieldKind::Concealed,
                value: "TOKEN-SUPER-SECRET".into(),
                purpose: Some(FieldPurpose::Password),
                section_id: None,
            }],
            ..Default::default()
        };
        let rendered = format!("{login:?} {:?}", login.custom_fields[0]);
        for secret in [
            "alice@example.com",
            "hunter2-SUPER-SECRET",
            "JBSWY3DPEHPK3PXP",
            "TOKEN-SUPER-SECRET",
        ] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked a content subtype secret: {rendered}"
            );
        }
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn round_trip_login() {
        let ck = ItemContentKey::random();
        let item_id = uuid::Uuid::new_v4();
        let (notes_doc, notes_text) = crate::prose::from_plaintext("imported from 1Password");
        let login = ItemContent::Login(LoginContent {
            username: "alice@example.com".into(),
            password: "hunter2".into(),
            urls: vec!["https://example.com".into()],
            totp: Some(TotpConfig {
                secret_base32: "JBSWY3DPEHPK3PXP".into(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period_seconds: 30,
            }),
            notes: notes_doc,
            notes_text,
            custom_fields: vec![CustomField {
                name: "API note".into(),
                kind: CustomFieldKind::String,
                value: "internal only".into(),
                purpose: None,
                section_id: None,
            }],
            password_history: Vec::new(),
            raw_import: serde_json::json!({"opVersion": "8"}).into(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &login).unwrap();
        let recovered = decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap();
        assert_eq!(login, recovered);
    }

    #[test]
    fn item_id_aad_prevents_swap() {
        let ck = ItemContentKey::random();
        let item_a = uuid::Uuid::new_v4();
        let item_b = uuid::Uuid::new_v4();
        let (body_doc, body_text) = crate::prose::from_plaintext("x");
        let login = ItemContent::SecureNote(SecureNoteContent {
            body: body_doc,
            body_text,
            custom_fields: vec![],
            raw_import: Default::default(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_a.as_bytes(), &login).unwrap();
        let err = decrypt_item_with_content_key(&ck, item_b.as_bytes(), &blob).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn title_round_trip() {
        let vk = VaultKey::random();
        let item_id = uuid::Uuid::new_v4();
        let blob = encrypt_title(&vk, item_id.as_bytes(), "Example Login");
        let recovered = decrypt_title(&vk, item_id.as_bytes(), &blob).unwrap();
        assert_eq!(recovered, "Example Login");
    }

    #[test]
    fn default_login_has_valid_prosemirror_doc() {
        // Derived Default routes through ProseDoc::default which guarantees
        // a real ProseMirror doc rather than serde_json::Value::Null.
        let login = LoginContent::default();
        assert_eq!(login.notes.as_value()["type"], "doc");
        assert!(login.notes.as_value()["content"].is_array());
        let note = SecureNoteContent::default();
        assert_eq!(note.body.as_value()["type"], "doc");
        assert!(note.body.as_value()["content"].is_array());
    }

    #[test]
    fn empty_object_deserializes_to_valid_doc() {
        // Missing-key deserialization routes through ProseDoc::default and
        // yields a real ProseMirror doc.
        let parsed: LoginContent = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.notes.as_value()["type"], "doc");
        let parsed: SecureNoteContent = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed.body.as_value()["type"], "doc");
    }

    #[test]
    fn explicit_null_doc_deserializes_to_valid_doc() {
        let parsed: LoginContent = serde_json::from_str(r#"{ "notes": null }"#).unwrap();
        assert_eq!(parsed.notes.as_value()["type"], "doc");
        let parsed: SecureNoteContent = serde_json::from_str(r#"{ "body": null }"#).unwrap();
        assert_eq!(parsed.body.as_value()["type"], "doc");
        let parsed: ApiCredentialContent =
            serde_json::from_str(r#"{ "kind": "api_key", "primary_value": "k", "notes": null }"#)
                .unwrap();
        assert_eq!(parsed.notes.as_value()["type"], "doc");
    }

    #[test]
    fn round_trip_preserves_non_empty_prosemirror_doc() {
        // Encrypt/decrypt must preserve a non-trivial ProseMirror tree
        // bit-for-bit, including nodes that older clients might not know
        // about. Unknown node kinds are forward-compatible by construction.
        let ck = ItemContentKey::random();
        let item_id = uuid::Uuid::new_v4();
        let raw = serde_json::json!({
            "type": "doc",
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 1},
                    "content": [{"type": "text", "text": "Rotation runbook"}]
                },
                {
                    "type": "paragraph",
                    "content": [
                    {"type": "text", "text": "see "},
                    {"type": "text", "marks": [{"type": "code"}], "text": "scripts/rotate.sh"}
                    ]
                },
                {
                    "type": "attachment",
                    "attrs": {"href": "seren-secrets://attachment/00000000-0000-0000-0000-000000000001"}
                }
            ]
        });
        let doc = crate::prose::ProseDoc::from_value_lossy(raw.clone());
        let body_text = doc.plain_text();
        let content = ItemContent::SecureNote(SecureNoteContent {
            body: doc.clone(),
            body_text: body_text.clone(),
            custom_fields: vec![],
            raw_import: ZeroizableJson::default(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &content).unwrap();
        let recovered = decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap();
        match recovered.as_ref() {
            ItemContent::SecureNote(n) => {
                assert_eq!(n.body.as_value(), &raw);
                assert_eq!(n.body_text, body_text);
            }
            _ => panic!("variant mismatch"),
        }
    }

    #[test]
    fn api_credential_round_trips_through_aead() {
        // Pins the wire-shape fix for the ApiCredentialContent kind field.
        // Without `#[serde(rename = "credential_kind")]`, the internally
        // tagged outer enum and the inner kind both serialize as `"kind"`,
        // and the second value wins on deserialization, breaking the round
        // trip entirely.
        let ck = ItemContentKey::random();
        let item_id = uuid::Uuid::new_v4();
        let content = ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::ApiKey,
            primary_value: "ak_live_primary".into(),
            secondary_value: "ak_live_secondary".into(),
            custom_fields: vec![CustomField {
                name: "POLY_API_KEY".into(),
                kind: CustomFieldKind::Concealed,
                value: "secret-1".into(),
                purpose: None,
                section_id: None,
            }],
            raw_import: ZeroizableJson::default(),
            ..Default::default()
        });

        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &content).unwrap();
        let recovered = decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap();

        let ItemContent::ApiCredential(api) = recovered.as_ref() else {
            panic!("variant mismatch");
        };
        assert_eq!(api.kind, ApiCredentialKind::ApiKey);
        assert_eq!(api.primary_value, "ak_live_primary");
        assert_eq!(api.secondary_value, "ak_live_secondary");
        assert_eq!(api.custom_fields.len(), 1);
        assert_eq!(api.custom_fields[0].name, "POLY_API_KEY");
        assert_eq!(api.custom_fields[0].value, "secret-1");
    }

    #[test]
    fn api_credential_wire_uses_renamed_inner_kind() {
        // The outer ItemContent tag stays "kind"; the inner credential
        // kind moves to "credential_kind" to avoid the duplicate field.
        let content = ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::ApiKey,
            ..Default::default()
        });
        let value = serde_json::to_value(&content).unwrap();
        assert_eq!(value["kind"], "api_credential");
        assert_eq!(value["credential_kind"], "api_key");
        assert!(value.as_object().unwrap().get("kind").unwrap().is_string());
    }

    #[test]
    fn login_urls_reject_invalid_array_entries() {
        // URL entries must carry an explicit URL string.
        let null_entry = serde_json::json!({
            "kind": "login",
            "urls": [null]
        });
        assert!(serde_json::from_value::<ItemContent>(null_entry).is_err());

        let empty_object = serde_json::json!({
            "kind": "login",
            "urls": [{}]
        });
        assert!(serde_json::from_value::<ItemContent>(empty_object).is_err());

        let only_match_type = serde_json::json!({
            "kind": "login",
            "urls": [{ "match_type": "exact" }]
        });
        assert!(serde_json::from_value::<ItemContent>(only_match_type).is_err());

        let empty_string = serde_json::json!({
            "kind": "login",
            "urls": [""]
        });
        assert!(serde_json::from_value::<ItemContent>(empty_string).is_err());
    }

    #[test]
    fn login_urls_require_structured_entries() {
        let bare = serde_json::json!({
            "kind": "login",
            "username": "alice",
            "password": "hunter2",
            "urls": ["https://example.com", "https://example.org"]
        });
        assert!(serde_json::from_value::<ItemContent>(bare).is_err());

        let structured = serde_json::json!({
            "kind": "login",
            "username": "alice",
            "password": "hunter2",
            "urls": [
                { "url": "https://example.com", "match_type": "exact" },
                { "url": "https://example.org" }
            ]
        });
        let content: ItemContent = serde_json::from_value(structured).unwrap();
        match content {
            ItemContent::Login(login) => {
                assert_eq!(login.urls[0].match_type, Some(UrlMatchType::Exact));
                assert!(login.urls[1].match_type.is_none());
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn round_trip_identity_card_ssh_document() {
        let ck = ItemContentKey::random();
        let item_id = uuid::Uuid::new_v4();
        let identity = ItemContent::Identity(IdentityContent {
            first_name: "Alice".into(),
            last_name: "Example".into(),
            emails: vec![EmailEntry {
                label: String::new(),
                value: "alice@example.com".into(),
            }],
            phones: vec![PhoneEntry {
                label: String::new(),
                value: "+1-555-0100".into(),
            }],
            addresses: vec![PostalAddress {
                street: "1 Test Way".into(),
                city: "Springfield".into(),
                region: "IL".into(),
                postal_code: "62701".into(),
                country: "USA".into(),
            }],
            government_ids: vec![GovernmentId {
                label: "US passport".into(),
                number: "P00000000".into(),
                issued_on: Some("2020-01-01".into()),
                expires_on: Some("2030-01-01".into()),
                issuer: "US Department of State".into(),
            }],
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &identity).unwrap();
        let recovered = decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap();
        assert_eq!(recovered, identity);

        let card = ItemContent::Card(CardContent {
            cardholder_name: "Alice Example".into(),
            number: "4242424242424242".into(),
            brand: "Visa".into(),
            expiry: "12/30".into(),
            cvv: "123".into(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &card).unwrap();
        assert_eq!(
            decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap(),
            card
        );

        let ssh = ItemContent::SshKey(SshKeyContent {
            private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\n...".into(),
            public_key: "ssh-ed25519 AAAA...".into(),
            passphrase: "p4ss".into(),
            fingerprint: "SHA256:abc".into(),
            key_type: "ed25519".into(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &ssh).unwrap();
        assert_eq!(
            decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap(),
            ssh
        );

        let document = ItemContent::Document(DocumentContent {
            filename: "passport.pdf".into(),
            content_type: "application/pdf".into(),
            size_bytes: Some(123_456),
            alt_text: "passport scan".into(),
            attachment_uri: "seren-secrets://attachment/00000000-0000-0000-0000-000000000000"
                .into(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &document).unwrap();
        assert_eq!(
            decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap(),
            document
        );
    }

    #[test]
    fn metadata_round_trips() {
        let vk = VaultKey::random();
        let item_id = uuid::Uuid::new_v4();
        let tags = vec!["prod".to_string(), "database".to_string()];
        let tag_blob = encrypt_tags(&vk, item_id.as_bytes(), &tags).unwrap();
        assert_eq!(
            decrypt_tags(&vk, item_id.as_bytes(), &tag_blob).unwrap(),
            tags
        );

        let last_used = "2026-05-21T00:00:00Z";
        let used_blob = encrypt_last_used(&vk, item_id.as_bytes(), last_used);
        assert_eq!(
            decrypt_last_used(&vk, item_id.as_bytes(), &used_blob).unwrap(),
            last_used
        );
    }

    #[test]
    fn content_key_round_trip() {
        let vk = VaultKey::random();
        let item_id = uuid::Uuid::new_v4();
        let ck = generate_item_content_key();

        // Wrap the content key under the vault key, then unwrap it back
        // out and confirm the bytes are preserved.
        let wrapped = wrap_item_content_key(&vk, item_id.as_bytes(), &ck);
        let recovered = unwrap_item_content_key(&vk, item_id.as_bytes(), &wrapped).unwrap();
        assert_eq!(recovered.as_bytes(), ck.as_bytes());

        // Body round-trip under the content key.
        let (notes_doc, notes_text) = crate::prose::from_plaintext("hello");
        let login = ItemContent::Login(LoginContent {
            username: "alice".into(),
            password: "hunter2".into(),
            urls: vec!["https://example.com".into()],
            totp: None,
            notes: notes_doc,
            notes_text,
            custom_fields: vec![],
            password_history: vec![],
            raw_import: ZeroizableJson::default(),
            ..Default::default()
        });
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &login).unwrap();
        let decrypted = decrypt_item_with_content_key(&ck, item_id.as_bytes(), &blob).unwrap();
        assert_eq!(decrypted, login);
    }

    #[test]
    fn content_key_wrap_rejects_other_vaults() {
        // Wrapping under one vault key cannot be unwrapped under another.
        // Guards against a stale or stolen vault-key reference recovering
        // someone else's per-item content key.
        let vk1 = VaultKey::random();
        let vk2 = VaultKey::random();
        let item_id = uuid::Uuid::new_v4();
        let ck = generate_item_content_key();
        let wrapped = wrap_item_content_key(&vk1, item_id.as_bytes(), &ck);
        let err = unwrap_item_content_key(&vk2, item_id.as_bytes(), &wrapped).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn content_key_wrap_rejects_other_items() {
        // Same vault, different item id: AAD differs so unwrap fails.
        // Prevents one item's wrap from being replayed as another item's.
        let vk = VaultKey::random();
        let item_a = uuid::Uuid::new_v4();
        let item_b = uuid::Uuid::new_v4();
        let ck = generate_item_content_key();
        let wrapped = wrap_item_content_key(&vk, item_a.as_bytes(), &ck);
        let err = unwrap_item_content_key(&vk, item_b.as_bytes(), &wrapped).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn body_under_content_key_isolated_from_other_keys() {
        // Body sealed under one content key cannot be opened under any
        // other key, even after a correct unwrap. This is the property
        // the share/approval flow relies on: handing off a content key
        // for item A says nothing about item B's content key.
        let item_id = uuid::Uuid::new_v4();
        let ck = generate_item_content_key();
        let other_ck = generate_item_content_key();
        let content = ItemContent::SecureNote(SecureNoteContent::default());
        let blob = encrypt_item_with_content_key(&ck, item_id.as_bytes(), &content).unwrap();
        let err = decrypt_item_with_content_key(&other_ck, item_id.as_bytes(), &blob).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    const SENTINEL: &str = "SENTINEL_SECRET_a7f39c2b";

    /// Serialize, confirm the sentinel is present, scrub, and confirm every
    /// occurrence is gone. Derived `Zeroize` requires every field to be
    /// scrub-capable; this guards custom field wrappers and type-level
    /// implementations against missing plaintext.
    fn assert_scrubbed(mut content: ItemContent) {
        use zeroize::Zeroize;
        let before = serde_json::to_string(&content).unwrap();
        assert!(
            before.contains(SENTINEL),
            "test fixture must embed the sentinel before scrubbing"
        );
        content.zeroize();
        let after = serde_json::to_string(&content).unwrap();
        assert!(
            !after.contains(SENTINEL),
            "decrypted secret survived zeroize: {after}"
        );
    }

    fn s() -> String {
        SENTINEL.to_string()
    }

    fn prose() -> crate::prose::ProseDoc {
        crate::prose::from_plaintext(SENTINEL).0
    }

    fn raw_import() -> ZeroizableJson {
        ZeroizableJson(
            serde_json::json!({ "leftover": SENTINEL, "nested": [SENTINEL, { "value": SENTINEL }] }),
        )
    }

    fn custom_field() -> CustomField {
        CustomField {
            name: s(),
            kind: CustomFieldKind::Concealed,
            value: s(),
            purpose: Some(FieldPurpose::Password),
            section_id: Some(s()),
        }
    }

    fn section() -> Section {
        Section {
            id: s(),
            title: s(),
        }
    }

    fn address() -> PostalAddress {
        PostalAddress {
            street: s(),
            city: s(),
            region: s(),
            postal_code: s(),
            country: s(),
        }
    }

    #[test]
    fn zeroize_scrubs_login_and_all_login_leaf_types() {
        assert_scrubbed(ItemContent::Login(LoginContent {
            username: s(),
            password: s(),
            urls: vec![LoginUrl::plain(SENTINEL)],
            totp: Some(TotpConfig {
                secret_base32: s(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period_seconds: 30,
            }),
            notes: crate::prose::from_plaintext(SENTINEL).0,
            notes_text: s(),
            custom_fields: vec![CustomField {
                name: s(),
                kind: CustomFieldKind::Concealed,
                value: s(),
                purpose: Some(FieldPurpose::Password),
                section_id: Some(s()),
            }],
            password_history: vec![PasswordHistoryEntry {
                password: s(),
                changed_at: s(),
            }],
            generator_recipe: Some(GeneratorRecipe {
                excluded_characters: s(),
                word_delimiter: s(),
                ..Default::default()
            }),
            autofill_on_page_load: Some(true),
            fido2_credentials: vec![Fido2Credential {
                credential_id: s(),
                user_handle: s(),
                rp_id: s(),
                rp_name: s(),
                user_name: s(),
                user_display_name: s(),
                algorithm: s(),
                private_key: s(),
                counter: 0,
                discoverable: true,
                created_at: s(),
            }],
            sections: vec![Section {
                id: s(),
                title: s(),
            }],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_identity_and_its_leaf_types() {
        assert_scrubbed(ItemContent::Identity(IdentityContent {
            first_name: s(),
            middle_name: s(),
            last_name: s(),
            username: s(),
            company: s(),
            job_title: s(),
            gender: s(),
            date_of_birth: Some(s()),
            emails: vec![EmailEntry {
                label: s(),
                value: s(),
            }],
            phones: vec![PhoneEntry {
                label: s(),
                value: s(),
            }],
            addresses: vec![address()],
            government_ids: vec![GovernmentId {
                label: s(),
                number: s(),
                issued_on: Some(s()),
                expires_on: Some(s()),
                issuer: s(),
            }],
            notes: crate::prose::from_plaintext(SENTINEL).0,
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_secure_note_content() {
        assert_scrubbed(ItemContent::SecureNote(SecureNoteContent {
            body: prose(),
            body_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_api_credential_headers_and_rotation() {
        let mut headers = ZeroizableBTreeMap::default();
        headers.0.insert(s(), s());
        assert_scrubbed(ItemContent::ApiCredential(ApiCredentialContent {
            kind: ApiCredentialKind::Oauth2Token,
            primary_value: s(),
            secondary_value: s(),
            headers,
            rotation: Some(RotationPolicy {
                policy: RotationPolicyKind::Scheduled,
                next_rotation_at: Some(s()),
            }),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_card_and_crypto_wallet_leaf_types() {
        assert_scrubbed(ItemContent::Card(CardContent {
            cardholder_name: s(),
            number: s(),
            brand: s(),
            expiry: s(),
            cvv: s(),
            pin: s(),
            billing_address: Some(address()),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));

        assert_scrubbed(ItemContent::CryptoWallet(CryptoWalletContent {
            wallet_name: s(),
            network: s(),
            seed_phrase: s(),
            private_key: s(),
            password: s(),
            derivation_path: s(),
            addresses: vec![WalletAddress {
                label: s(),
                address: s(),
            }],
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_ssh_key_and_document_content() {
        assert_scrubbed(ItemContent::SshKey(SshKeyContent {
            private_key: s(),
            public_key: s(),
            passphrase: s(),
            fingerprint: "SHA256:metadata".to_string(),
            key_type: "ed25519".to_string(),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));

        assert_scrubbed(ItemContent::Document(DocumentContent {
            filename: s(),
            content_type: s(),
            size_bytes: Some(123),
            alt_text: s(),
            attachment_uri: s(),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_financial_and_identity_document_content() {
        assert_scrubbed(ItemContent::BankAccount(BankAccountContent {
            bank_name: s(),
            account_holder: s(),
            account_number: s(),
            routing_number: s(),
            account_type: s(),
            iban: s(),
            swift: s(),
            branch: s(),
            pin: s(),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));

        assert_scrubbed(ItemContent::Passport(PassportContent {
            number: s(),
            passport_type: s(),
            full_name: s(),
            surname: s(),
            given_names: s(),
            nationality: s(),
            date_of_birth: Some(s()),
            place_of_birth: s(),
            gender: s(),
            issuing_country: s(),
            issuing_authority: s(),
            issued_on: Some(s()),
            expires_on: Some(s()),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));

        assert_scrubbed(ItemContent::DriverLicense(DriverLicenseContent {
            number: s(),
            full_name: s(),
            date_of_birth: Some(s()),
            gender: s(),
            address: Some(address()),
            country: s(),
            state: s(),
            license_class: s(),
            conditions: s(),
            issued_on: Some(s()),
            expires_on: Some(s()),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }

    #[test]
    fn zeroize_scrubs_server_and_database_content() {
        assert_scrubbed(ItemContent::Server(ServerContent {
            hostname: s(),
            port: Some(22),
            protocol: s(),
            username: s(),
            password: s(),
            ssh_key_reference: s(),
            admin_console_url: s(),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));

        assert_scrubbed(ItemContent::Database(DatabaseContent {
            database_type: s(),
            server: s(),
            port: Some(5432),
            database_name: s(),
            username: s(),
            password: s(),
            sid: s(),
            schema: s(),
            notes: prose(),
            notes_text: s(),
            custom_fields: vec![custom_field()],
            sections: vec![section()],
            raw_import: raw_import(),
        }));
    }
}

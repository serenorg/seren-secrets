//! Bitwarden encrypted JSON importer.
//!
//! Bitwarden's encrypted export format is:
//!
//! ```json
//! {
//!   "encrypted": true,
//!   "passwordProtected": true,
//!   "salt": "<base64>",
//!   "kdfType": 0,
//!   "kdfIterations": 600000,
//!   "kdfMemory": 64,         // present when kdfType == 1
//!   "kdfParallelism": 4,     // present when kdfType == 1
//!   "encKeyValidation_DO_NOT_EDIT": "2.<iv_b64>|<ct_b64>|<mac_b64>",
//!   "data": "2.<iv_b64>|<ct_b64>|<mac_b64>"
//! }
//! ```
//!
//! Key derivation:
//!
//! - `kdfType == 0` (PBKDF2-SHA256): `key = PBKDF2-HMAC-SHA256(password, salt,
//!   iterations, 32)`.
//! - `kdfType == 1` (Argon2id): `key = Argon2id(password, salt, t=iterations,
//!   m=memory_MiB, p=parallelism, 32)`.
//!
//! Then HKDF-SHA256 stretches `key` into `(enc_key || mac_key)` of 32 bytes
//! each, with info strings `"enc"` and `"mac"`.
//!
//! The encrypted-string format `2.<iv_b64>|<ct_b64>|<mac_b64>` is
//! `AesCbc256_HmacSha256_B64`:
//!
//! - iv: 16 random bytes (the AES-CBC IV)
//! - ct: AES-256-CBC ciphertext padded with PKCS7
//! - mac: HMAC-SHA256(iv || ct) under `mac_key`
//!
//! Encrypt-then-MAC; the MAC is verified in constant time before any AES
//! work.
//!
//! ## Verification status
//!
//! The pipeline is round-trip tested against itself (encrypt with the same
//! scheme, decrypt via the importer, expect bytes-back). It has NOT yet been
//! validated against a real Bitwarden export. Before relying on this in
//! production, run a real export through it and confirm the inner JSON
//! parses correctly.

use crate::error::{CryptoError, CryptoResult};
use crate::import::ImportedItem;
use crate::import::otpauth::parse_otpauth_uri;
use crate::protocol::item::{
    ApiCredentialContent, ApiCredentialKind, CardContent, CustomField, CustomFieldKind,
    Fido2Credential, GovernmentId, IdentityContent, LoginContent, LoginUrl, PasswordHistoryEntry,
    PostalAddress, SecureNoteContent, SshKeyContent, TotpAlgorithm, TotpConfig, UrlMatchType,
};

use aes::Aes256;
use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cbc::Decryptor as CbcDecryptor;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

// Upper bound on any individual base64-decoded enc-string component (iv, ct,
// or mac). 64 MiB is well above any plausible real-world Bitwarden export
// item.
const MAX_ENC_STRING_COMPONENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_SALT_BYTES: usize = 1024;
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
const MAX_ARGON2_MEMORY_MIB: u64 = 1024;
const MAX_ARGON2_ITERATIONS: u32 = 32;
const MAX_ARGON2_PARALLELISM: u32 = 64;

type Aes256CbcDec = CbcDecryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
pub enum BitwardenImportError {
    #[error("envelope is not a Bitwarden encrypted export")]
    NotEncryptedExport,
    #[error("envelope is a Bitwarden encrypted export")]
    EncryptedExport,
    #[error("unsupported kdf type: {0}")]
    UnsupportedKdf(u32),
    #[error("kdf parameters exceed importer safety limits")]
    KdfParamsTooLarge,
    #[error("malformed encrypted-string: {0}")]
    MalformedEncString(&'static str),
    #[error("MAC verification failed; wrong password or tampered export")]
    MacFailure,
    #[error("AES decrypt failed")]
    AesFailure,
    #[error("inner JSON parse failed")]
    InnerJson,
    #[error("envelope JSON parse failed")]
    EnvelopeJson,
}

impl From<BitwardenImportError> for CryptoError {
    fn from(err: BitwardenImportError) -> Self {
        // Preserve the original variant for callers that need to branch on
        // it via Result<_, BitwardenImportError>; the conversion to
        // CryptoError loses that detail but matches the wider importer
        // surface.
        match err {
            BitwardenImportError::MacFailure => CryptoError::AuthFailure,
            BitwardenImportError::EnvelopeJson | BitwardenImportError::InnerJson => {
                CryptoError::Import("bitwarden json parse")
            }
            BitwardenImportError::NotEncryptedExport => {
                CryptoError::Import("bitwarden export is not encrypted")
            }
            BitwardenImportError::EncryptedExport => {
                CryptoError::Import("bitwarden export is encrypted")
            }
            BitwardenImportError::UnsupportedKdf(_) => CryptoError::Import("bitwarden kdf type"),
            BitwardenImportError::KdfParamsTooLarge => CryptoError::Kdf("bitwarden kdf params"),
            BitwardenImportError::MalformedEncString(_) => {
                CryptoError::Import("bitwarden encrypted string")
            }
            BitwardenImportError::AesFailure => CryptoError::Import("bitwarden aes decrypt"),
        }
    }
}

/// Decrypt a Bitwarden encrypted JSON export with the given master password
/// and return the typed item stream. Runs entirely client-side; the password
/// never leaves this process.
pub fn import_bitwarden_encrypted_json(
    payload: &[u8],
    master_password: &[u8],
) -> CryptoResult<Vec<ImportedItem>> {
    let envelope: Envelope =
        serde_json::from_slice(payload).map_err(|_| BitwardenImportError::EnvelopeJson)?;

    if !envelope.encrypted {
        return Err(BitwardenImportError::NotEncryptedExport.into());
    }

    if encoded_len_exceeds_decoded_cap(envelope.salt.len(), MAX_SALT_BYTES) {
        return Err(BitwardenImportError::KdfParamsTooLarge.into());
    }
    let salt = B64
        .decode(envelope.salt.as_bytes())
        .map_err(|_| BitwardenImportError::EnvelopeJson)?;
    if salt.len() > MAX_SALT_BYTES {
        return Err(BitwardenImportError::KdfParamsTooLarge.into());
    }
    let master_key = derive_master_key(master_password, &salt, &envelope)?;
    let (enc_key, mac_key) = stretch_keys(&master_key);
    let enc_key_ref: &[u8; 32] = &enc_key;
    let mac_key_ref: &[u8; 32] = &mac_key;

    // Bitwarden ships a separate `encKeyValidation_DO_NOT_EDIT` field that
    // wraps a known-plaintext sentinel under the same (enc_key, mac_key) pair.
    // Because every enc-string is independently authenticated via HMAC over
    // iv || ct, a wrong password (or tampered MAC) already fails loudly when
    // we decrypt the data field. The validation field is exercised purely to
    // surface AuthFailure on shorter inputs without scanning the full data
    // payload first, and to round-trip exports that ship it. The decrypted
    // sentinel value itself is intentionally discarded.
    let _validation = decrypt_enc_string(&envelope.enc_key_validation, enc_key_ref, mac_key_ref)?;

    let plaintext = decrypt_enc_string(&envelope.data, enc_key_ref, mac_key_ref)?;
    let inner: BitwardenInner =
        serde_json::from_slice(&plaintext).map_err(|_| BitwardenImportError::InnerJson)?;

    Ok(inner.into_items())
}

/// Decode a Bitwarden unencrypted JSON export into normalized item data.
pub fn import_bitwarden_json(payload: &[u8]) -> CryptoResult<Vec<ImportedItem>> {
    let marker: BitwardenEnvelopeMarker =
        serde_json::from_slice(payload).map_err(|_| BitwardenImportError::EnvelopeJson)?;
    if marker.encrypted.unwrap_or(false) {
        return Err(BitwardenImportError::EncryptedExport.into());
    }
    let inner: BitwardenInner =
        serde_json::from_slice(payload).map_err(|_| BitwardenImportError::InnerJson)?;
    Ok(inner.into_items())
}

fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    envelope: &Envelope,
) -> CryptoResult<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    match envelope.kdf_type {
        0 => {
            // Import accepts old Bitwarden iteration counts; only cap CPU cost.
            let iterations = envelope.kdf_iterations.max(1);
            if iterations > MAX_PBKDF2_ITERATIONS {
                return Err(BitwardenImportError::KdfParamsTooLarge.into());
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, out.as_mut());
        }
        1 => {
            use argon2::{Algorithm, Argon2, Params, Version};
            // kdfMemory is the user-facing MiB value; argon2 expects KiB. Clamp
            // first into u32 to avoid silent truncation, then convert to KiB
            // with saturation so a malformed huge value cannot wrap.
            let memory_mib_u64 = envelope.kdf_memory.unwrap_or(64);
            if memory_mib_u64 > MAX_ARGON2_MEMORY_MIB {
                return Err(BitwardenImportError::KdfParamsTooLarge.into());
            }
            let memory_mib: u32 = u32::try_from(memory_mib_u64).unwrap_or(u32::MAX);
            let memory_kib = memory_mib.saturating_mul(1024);
            let time_cost = envelope.kdf_iterations.max(1);
            let parallelism = envelope.kdf_parallelism.unwrap_or(4).max(1);
            if time_cost > MAX_ARGON2_ITERATIONS || parallelism > MAX_ARGON2_PARALLELISM {
                return Err(BitwardenImportError::KdfParamsTooLarge.into());
            }
            let params = Params::new(memory_kib, time_cost, parallelism, Some(32))
                .map_err(|_| CryptoError::Kdf("bitwarden argon2 params"))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon
                .hash_password_into(password, salt, out.as_mut())
                .map_err(|_| CryptoError::Kdf("bitwarden argon2 derivation"))?;
        }
        other => return Err(BitwardenImportError::UnsupportedKdf(other).into()),
    }
    Ok(out)
}

fn stretch_keys(master_key: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::from_prk(master_key).expect("PRK length is 32");
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", enc.as_mut()).expect("32 bytes fits HKDF");
    hk.expand(b"mac", mac.as_mut()).expect("32 bytes fits HKDF");
    (enc, mac)
}

fn decrypt_enc_string(
    enc_string: &str,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, BitwardenImportError> {
    let (enc_type, rest) =
        enc_string
            .split_once('.')
            .ok_or(BitwardenImportError::MalformedEncString(
                "missing type prefix",
            ))?;
    if enc_type != "2" {
        return Err(BitwardenImportError::MalformedEncString(
            "only AesCbc256_HmacSha256_B64 (type 2) is supported",
        ));
    }
    let parts: Vec<&str> = rest.split('|').collect();
    if parts.len() != 3 {
        return Err(BitwardenImportError::MalformedEncString(
            "expected iv|ct|mac",
        ));
    }
    // Bound each base64 input before decoding to bound the resulting Vec
    // allocation. The base64 expansion factor is 4/3, so capping the encoded
    // length is sufficient to cap the decoded length.
    if encoded_len_exceeds_decoded_cap(parts[0].len(), MAX_ENC_STRING_COMPONENT_BYTES)
        || encoded_len_exceeds_decoded_cap(parts[1].len(), MAX_ENC_STRING_COMPONENT_BYTES)
        || encoded_len_exceeds_decoded_cap(parts[2].len(), MAX_ENC_STRING_COMPONENT_BYTES)
    {
        return Err(BitwardenImportError::MalformedEncString(
            "enc-string component exceeds size cap",
        ));
    }
    let iv = B64
        .decode(parts[0].as_bytes())
        .map_err(|_| BitwardenImportError::MalformedEncString("iv base64"))?;
    let ct = B64
        .decode(parts[1].as_bytes())
        .map_err(|_| BitwardenImportError::MalformedEncString("ciphertext base64"))?;
    let mac = B64
        .decode(parts[2].as_bytes())
        .map_err(|_| BitwardenImportError::MalformedEncString("mac base64"))?;

    if iv.len() != 16 {
        return Err(BitwardenImportError::MalformedEncString(
            "iv must be 16 bytes",
        ));
    }
    // AES-CBC ciphertext must be a positive multiple of the 16-byte block size
    // for PKCS7 unpadding to even have a chance; catching this before the MAC
    // check rejects obviously malformed inputs without changing the constant-
    // time MAC behavior on well-formed inputs.
    if ct.is_empty() || ct.len() % 16 != 0 {
        return Err(BitwardenImportError::MalformedEncString(
            "ciphertext length must be a positive multiple of 16",
        ));
    }

    // HMAC-SHA256(iv || ct) under mac_key, constant-time compared.
    let mut hmac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any 32-byte key");
    hmac.update(&iv);
    hmac.update(&ct);
    let expected = hmac.finalize().into_bytes();
    if mac.len() != expected.len() || mac.ct_eq(expected.as_slice()).unwrap_u8() == 0 {
        return Err(BitwardenImportError::MacFailure);
    }

    let mut iv_arr = [0u8; 16];
    iv_arr.copy_from_slice(&iv);
    // The ciphertext buffer is decrypted in place. After unpadding the slice
    // returned by `decrypt_padded` is a prefix of `ct_buf`; the tail still
    // holds plaintext bytes from the final block, so the whole buffer must be
    // zeroized when it drops.
    let mut ct_buf: Zeroizing<Vec<u8>> = Zeroizing::new(ct);
    let decryptor = Aes256CbcDec::new(enc_key.into(), &iv_arr.into());
    let plaintext_len = decryptor
        .decrypt_padded::<Pkcs7>(ct_buf.as_mut())
        .map_err(|_| BitwardenImportError::AesFailure)?
        .len();
    let mut plaintext = Zeroizing::new(Vec::with_capacity(plaintext_len));
    plaintext.extend_from_slice(&ct_buf[..plaintext_len]);
    Ok(plaintext)
}

fn encoded_len_exceeds_decoded_cap(encoded_len: usize, decoded_cap: usize) -> bool {
    let max_encoded_len = decoded_cap
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(4);
    encoded_len > max_encoded_len
}

// ---------------------------------------------------------------------------
// Envelope and inner-JSON shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    #[serde(default)]
    encrypted: bool,
    salt: String,
    #[serde(default)]
    kdf_type: u32,
    #[serde(default = "default_iterations")]
    kdf_iterations: u32,
    #[serde(default)]
    kdf_memory: Option<u64>,
    #[serde(default)]
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: String,
    data: String,
}

#[derive(Debug, Deserialize)]
struct BitwardenEnvelopeMarker {
    #[serde(default)]
    encrypted: Option<bool>,
}

fn default_iterations() -> u32 {
    600_000
}

#[derive(Debug, Deserialize)]
struct BitwardenInner {
    #[serde(default)]
    folders: Vec<Folder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct Folder {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct BwItem {
    name: String,
    #[serde(default, rename = "type")]
    item_type: u32,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default, rename = "folderId")]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
    /// Populated when item_type == 3 (Card). Bitwarden's card subobject
    /// carries cardholder name, brand, PAN, expiry split into month/year,
    /// and the verification code.
    #[serde(default)]
    card: Option<BwCard>,
    /// Populated when item_type == 4 (Identity).
    #[serde(default)]
    identity: Option<BwIdentity>,
    /// Populated when item_type == 5 (SSH Key) on Bitwarden builds that
    /// support it. Older exports leave this `None` even for users who
    /// have SSH keys stored, so the importer falls back to passthrough.
    #[serde(default, rename = "sshKey")]
    ssh_key: Option<BwSshKey>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    #[serde(default, rename = "passwordHistory")]
    password_history: Option<Vec<BwPasswordHistory>>,
    #[serde(default)]
    reprompt: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BwCard {
    #[serde(default, rename = "cardholderName")]
    cardholder_name: Option<String>,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    number: Option<String>,
    #[serde(default, rename = "expMonth")]
    exp_month: Option<String>,
    #[serde(default, rename = "expYear")]
    exp_year: Option<String>,
    /// CVV / CVC. Bitwarden stores this under the `code` key.
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwIdentity {
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "firstName")]
    first_name: Option<String>,
    #[serde(default, rename = "middleName")]
    middle_name: Option<String>,
    #[serde(default, rename = "lastName")]
    last_name: Option<String>,
    #[serde(default)]
    address1: Option<String>,
    #[serde(default)]
    address2: Option<String>,
    #[serde(default)]
    address3: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default, rename = "postalCode")]
    postal_code: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    ssn: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default, rename = "passportNumber")]
    passport_number: Option<String>,
    #[serde(default, rename = "licenseNumber")]
    license_number: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwSshKey {
    #[serde(default, rename = "privateKey")]
    private_key: Option<String>,
    #[serde(default, rename = "publicKey")]
    public_key: Option<String>,
    #[serde(default, rename = "keyFingerprint")]
    key_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default, rename = "fido2Credentials")]
    fido2_credentials: Option<Vec<BwFido2Credential>>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
    /// Bitwarden URI match strategy.
    /// 0 = Default (host match), 1 = Host, 2 = StartsWith, 3 = Exact,
    /// 4 = Regex, 5 = Never. Older exports omit this; we treat that the
    /// same as Default.
    #[serde(default, rename = "match")]
    match_strategy: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BwField {
    name: String,
    #[serde(default)]
    value: Option<String>,
    #[serde(default, rename = "type")]
    field_type: u32,
    #[serde(default, rename = "linkedId")]
    linked_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct BwPasswordHistory {
    password: String,
    #[serde(default, rename = "lastUsedDate")]
    last_used_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwFido2Credential {
    #[serde(default, rename = "credentialId")]
    credential_id: String,
    #[serde(default, rename = "keyAlgorithm")]
    key_algorithm: String,
    #[serde(default, rename = "keyValue")]
    key_value: String,
    #[serde(default, rename = "rpId")]
    rp_id: String,
    #[serde(default, rename = "userHandle")]
    user_handle: Option<String>,
    #[serde(default, rename = "userName")]
    user_name: Option<String>,
    #[serde(default)]
    counter: String,
    #[serde(default, rename = "rpName")]
    rp_name: Option<String>,
    #[serde(default, rename = "userDisplayName")]
    user_display_name: Option<String>,
    #[serde(default)]
    discoverable: String,
    #[serde(default, rename = "creationDate")]
    creation_date: Option<String>,
}

impl BitwardenInner {
    fn into_items(self) -> Vec<ImportedItem> {
        let folder_names: std::collections::HashMap<String, String> =
            self.folders.into_iter().map(|f| (f.id, f.name)).collect();

        let mut out = Vec::with_capacity(self.items.len());
        for bw in self.items {
            let collection = bw
                .folder_id
                .as_ref()
                .and_then(|id| folder_names.get(id).cloned());
            let title = bw.name.clone();
            let notes = bw.notes.clone().unwrap_or_default();
            let favorite = bw.favorite;

            let item = match bw.item_type {
                1 => build_login(&bw, notes, favorite),
                2 => build_secure_note(notes, &bw, favorite),
                3 => build_card(&bw, notes, favorite),
                4 => build_identity(&bw, notes, favorite),
                5 => build_ssh_key(&bw, notes, favorite),
                // Anything else preserves the raw fields in
                // `raw_import` so the user can re-categorize later.
                _ => build_passthrough(&bw, notes, favorite),
            };

            let mut imported = item;
            imported.title = title;
            imported.source_collection = collection;
            out.push(imported);
        }
        out
    }
}

fn build_login(bw: &BwItem, notes: String, favorite: bool) -> ImportedItem {
    let login = bw.login.as_ref();
    let urls: Vec<LoginUrl> = login
        .and_then(|l| l.uris.as_ref())
        .map(|uris| {
            uris.iter()
                .filter_map(|u| {
                    let url = u.uri.as_deref()?;
                    if url.is_empty() {
                        return None;
                    }
                    Some(LoginUrl {
                        url: url.to_string(),
                        match_type: u.match_strategy.and_then(bitwarden_match_strategy),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let totp = login.and_then(|l| l.totp.as_deref().and_then(bitwarden_totp));
    let (notes_doc, notes_text) = crate::prose::from_plaintext(&notes);
    let content = LoginContent {
        username: login.and_then(|l| l.username.clone()).unwrap_or_default(),
        password: login.and_then(|l| l.password.clone()).unwrap_or_default(),
        urls,
        totp,
        notes: notes_doc,
        notes_text,
        custom_fields: convert_fields(bw),
        password_history: convert_password_history(bw.password_history.as_deref()),
        raw_import: serde_json::Value::Null,
        fido2_credentials: convert_fido2_credentials(login),
        ..Default::default()
    };
    let mut item = ImportedItem::new_login("", content);
    item.favorite = favorite;
    item
}

/// Map Bitwarden's URI match strategy integer to our `UrlMatchType`.
/// Returns `None` for 0 (Bitwarden's Default), which we treat as
/// "no hint" so the client can apply its own default (host match in
/// practice). Unknown integers also return `None` so a future Bitwarden
/// strategy we don't recognize falls through to client default.
fn bitwarden_match_strategy(strategy: u32) -> Option<UrlMatchType> {
    match strategy {
        1 => Some(UrlMatchType::Host),
        2 => Some(UrlMatchType::StartsWith),
        3 => Some(UrlMatchType::Exact),
        4 => Some(UrlMatchType::Regex),
        5 => Some(UrlMatchType::Never),
        _ => None,
    }
}

fn bitwarden_totp(secret: &str) -> Option<TotpConfig> {
    if secret.starts_with("otpauth://") {
        return parse_otpauth_uri(secret)
            .ok()
            .and_then(|item| match item.content {
                crate::protocol::item::ItemContent::Login(login) => login.totp,
                _ => None,
            });
    }
    // A raw secret must be valid base32 before it is stored, mirroring the
    // CSV importer; an invalid secret would silently emit wrong OTP codes.
    let secret_base32 = secret.replace([' ', '\t'], "").to_uppercase();
    if !super::otpauth::valid_base32(&secret_base32) {
        return None;
    }
    Some(TotpConfig {
        secret_base32,
        algorithm: TotpAlgorithm::Sha1,
        digits: 6,
        period_seconds: 30,
    })
}

fn build_secure_note(notes: String, bw: &BwItem, favorite: bool) -> ImportedItem {
    let (body_doc, body_text) = crate::prose::from_plaintext(&notes);
    let content = SecureNoteContent {
        body: body_doc,
        body_text,
        custom_fields: convert_fields(bw),
        raw_import: serde_json::Value::Null,
        ..Default::default()
    };
    let mut item = ImportedItem::new_secure_note("", content);
    item.favorite = favorite;
    item
}

fn build_passthrough(bw: &BwItem, notes: String, favorite: bool) -> ImportedItem {
    // Preserve the unknown-type item as an ApiCredential carrying its raw
    // fields. The user can re-categorize in the destination vault later.
    let (notes_doc, notes_text) = crate::prose::from_plaintext(&notes);
    let content = ApiCredentialContent {
        kind: ApiCredentialKind::ApiKey,
        primary_value: String::new(),
        secondary_value: String::new(),
        headers: std::collections::BTreeMap::new(),
        rotation: None,
        notes: notes_doc,
        notes_text,
        custom_fields: convert_fields(bw),
        sections: Vec::new(),
        raw_import: serde_json::json!({
            "bitwarden_type": bw.item_type,
            "reprompt": bw.reprompt,
        }),
    };
    let mut item = ImportedItem::new_api_credential("", content);
    item.favorite = favorite;
    item
}

/// Bitwarden type 3 (Card). Joins `expMonth` and `expYear` into the
/// `MM/YY` shape our `CardContent.expiry` carries; leaves either side
/// blank when the source did. Custom `BwField` entries flow into
/// `custom_fields` as usual.
fn build_card(bw: &BwItem, notes: String, favorite: bool) -> ImportedItem {
    let card = bw.card.as_ref();
    let (notes_doc, notes_text) = crate::prose::from_plaintext(&notes);
    let expiry = card
        .map(|c| format_card_expiry(c.exp_month.as_deref(), c.exp_year.as_deref()))
        .unwrap_or_default();
    let content = CardContent {
        cardholder_name: card
            .and_then(|c| c.cardholder_name.clone())
            .unwrap_or_default(),
        number: card.and_then(|c| c.number.clone()).unwrap_or_default(),
        brand: card.and_then(|c| c.brand.clone()).unwrap_or_default(),
        expiry,
        cvv: card.and_then(|c| c.code.clone()).unwrap_or_default(),
        pin: String::new(),
        billing_address: None,
        notes: notes_doc,
        notes_text,
        custom_fields: convert_fields(bw),
        sections: Vec::new(),
        raw_import: serde_json::json!({
            "bitwarden_type": 3,
            "reprompt": bw.reprompt,
        }),
    };
    let mut item = ImportedItem::new_card("", content);
    item.favorite = favorite;
    item
}

/// Format Bitwarden's split month/year into our `MM/YY` slot. Returns an
/// empty string when neither side is populated so the typed slot does
/// not display "//" for empty inputs.
fn format_card_expiry(month: Option<&str>, year: Option<&str>) -> String {
    let m = month.unwrap_or("").trim();
    let y = year.unwrap_or("").trim();
    if m.is_empty() && y.is_empty() {
        return String::new();
    }
    let m = if m.len() == 1 {
        format!("0{m}")
    } else {
        m.to_string()
    };
    // Truncate a four-digit year to two digits for visual consistency
    // with the MM/YY convention; clients that prefer MM/YYYY can read
    // the raw_import bag instead. `get` keeps a non-ASCII year (whose
    // byte length can also be 4) from slicing inside a codepoint.
    let y = if y.len() == 4 {
        y.get(2..).unwrap_or(y)
    } else {
        y
    };
    format!("{m}/{y}")
}

/// Bitwarden type 4 (Identity). Stitches the up-to-three address lines
/// into our flat `PostalAddress.street`, then maps remaining fields by
/// name. The `passportNumber`, `licenseNumber`, and `ssn` fields each
/// become a `GovernmentId` entry so an agent can resolve
/// `seren-secrets://v/i/passport_number` etc. via the alias dispatch in
/// `seren-secrets-resolver`.
fn build_identity(bw: &BwItem, notes: String, favorite: bool) -> ImportedItem {
    let id = bw.identity.as_ref();
    let (notes_doc, notes_text) = crate::prose::from_plaintext(&notes);

    let address = id.and_then(bitwarden_address);
    let mut government_ids: Vec<GovernmentId> = Vec::new();
    if let Some(id) = id {
        for (label, value) in [
            ("Passport number", id.passport_number.as_deref()),
            ("License number", id.license_number.as_deref()),
            ("Social Security Number", id.ssn.as_deref()),
        ] {
            if let Some(v) = value
                && !v.is_empty()
            {
                government_ids.push(GovernmentId {
                    label: label.to_string(),
                    number: v.to_string(),
                    issued_on: None,
                    expires_on: None,
                    issuer: String::new(),
                });
            }
        }
    }

    let custom_fields = convert_fields(bw);
    // Bitwarden Identity also carries username/title/company/email/phone;
    // we now have first-class slots for each (multiple emails/phones via
    // the EmailEntry/PhoneEntry shape), so promote them rather than
    // burying them in custom_fields.
    let mut emails: Vec<crate::protocol::item::EmailEntry> = Vec::new();
    if let Some(v) = id.and_then(|i| i.email.as_deref())
        && !v.is_empty()
    {
        emails.push(crate::protocol::item::EmailEntry {
            label: String::new(),
            value: v.to_string(),
        });
    }
    let mut phones: Vec<crate::protocol::item::PhoneEntry> = Vec::new();
    if let Some(v) = id.and_then(|i| i.phone.as_deref())
        && !v.is_empty()
    {
        phones.push(crate::protocol::item::PhoneEntry {
            label: String::new(),
            value: v.to_string(),
        });
    }
    let addresses: Vec<PostalAddress> = address.into_iter().collect();

    let content = IdentityContent {
        first_name: id.and_then(|i| i.first_name.clone()).unwrap_or_default(),
        middle_name: id.and_then(|i| i.middle_name.clone()).unwrap_or_default(),
        last_name: id.and_then(|i| i.last_name.clone()).unwrap_or_default(),
        username: id.and_then(|i| i.username.clone()).unwrap_or_default(),
        company: id.and_then(|i| i.company.clone()).unwrap_or_default(),
        job_title: id.and_then(|i| i.title.clone()).unwrap_or_default(),
        gender: String::new(),
        date_of_birth: None,
        emails,
        phones,
        addresses,
        government_ids,
        notes: notes_doc,
        notes_text,
        custom_fields,
        sections: Vec::new(),
        raw_import: serde_json::json!({
            "bitwarden_type": 4,
            "reprompt": bw.reprompt,
        }),
    };
    let mut item = ImportedItem::new_identity("", content);
    item.favorite = favorite;
    item
}

/// Collapse the up-to-three Bitwarden address lines into a single
/// `street` field separated by ", " and stitch the rest of the postal
/// pieces into `PostalAddress`. Returns `None` only when every component
/// is empty.
fn bitwarden_address(id: &BwIdentity) -> Option<PostalAddress> {
    let street_parts: Vec<String> = [&id.address1, &id.address2, &id.address3]
        .iter()
        .filter_map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .cloned()
        .collect();
    let address = PostalAddress {
        street: street_parts.join(", "),
        city: id.city.clone().unwrap_or_default(),
        region: id.state.clone().unwrap_or_default(),
        postal_code: id.postal_code.clone().unwrap_or_default(),
        country: id.country.clone().unwrap_or_default(),
    };
    let is_empty = address.street.is_empty()
        && address.city.is_empty()
        && address.region.is_empty()
        && address.postal_code.is_empty()
        && address.country.is_empty();
    if is_empty { None } else { Some(address) }
}

/// Bitwarden type 5 (SSH Key). Older Bitwarden builds export SSH keys as
/// generic items; newer ones include a dedicated `sshKey` subobject with
/// `privateKey`, `publicKey`, and `keyFingerprint`. When the subobject is
/// absent the importer passes the item through as a SecureNote because
/// the raw payload would otherwise have no shape we can map.
fn build_ssh_key(bw: &BwItem, notes: String, favorite: bool) -> ImportedItem {
    let Some(ssh) = bw.ssh_key.as_ref() else {
        return build_passthrough(bw, notes, favorite);
    };
    let (notes_doc, notes_text) = crate::prose::from_plaintext(&notes);
    let content = SshKeyContent {
        private_key: ssh.private_key.clone().unwrap_or_default(),
        public_key: ssh.public_key.clone().unwrap_or_default(),
        passphrase: String::new(),
        fingerprint: ssh.key_fingerprint.clone().unwrap_or_default(),
        key_type: String::new(),
        notes: notes_doc,
        notes_text,
        custom_fields: convert_fields(bw),
        sections: Vec::new(),
        raw_import: serde_json::json!({
            "bitwarden_type": 5,
            "reprompt": bw.reprompt,
        }),
    };
    let mut item = ImportedItem::new_ssh_key("", content);
    item.favorite = favorite;
    item
}

fn convert_fields(bw: &BwItem) -> Vec<CustomField> {
    bw.fields
        .as_deref()
        .map(|fs| {
            fs.iter()
                .map(|f| CustomField {
                    name: f.name.clone(),
                    kind: match f.field_type {
                        1 => CustomFieldKind::Concealed,
                        _ => CustomFieldKind::String,
                    },
                    purpose: None,
                    value: f
                        .value
                        .clone()
                        .or_else(|| {
                            f.linked_id
                                .and_then(|id| bitwarden_linked_field_value(bw, id))
                        })
                        .unwrap_or_default(),
                    section_id: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn bitwarden_linked_field_value(bw: &BwItem, linked_id: u32) -> Option<String> {
    match linked_id {
        100 => bw.login.as_ref()?.username.clone(),
        101 => bw.login.as_ref()?.password.clone(),
        300 => bw.card.as_ref()?.cardholder_name.clone(),
        301 => bw.card.as_ref()?.exp_month.clone(),
        302 => bw.card.as_ref()?.exp_year.clone(),
        303 => bw.card.as_ref()?.code.clone(),
        304 => bw.card.as_ref()?.brand.clone(),
        305 => bw.card.as_ref()?.number.clone(),
        400 => bw.identity.as_ref()?.title.clone(),
        401 => bw.identity.as_ref()?.middle_name.clone(),
        402 => bw.identity.as_ref()?.address1.clone(),
        403 => bw.identity.as_ref()?.address2.clone(),
        404 => bw.identity.as_ref()?.address3.clone(),
        405 => bw.identity.as_ref()?.city.clone(),
        406 => bw.identity.as_ref()?.state.clone(),
        407 => bw.identity.as_ref()?.postal_code.clone(),
        408 => bw.identity.as_ref()?.country.clone(),
        409 => bw.identity.as_ref()?.company.clone(),
        410 => bw.identity.as_ref()?.email.clone(),
        411 => bw.identity.as_ref()?.phone.clone(),
        412 => bw.identity.as_ref()?.ssn.clone(),
        413 => bw.identity.as_ref()?.username.clone(),
        414 => bw.identity.as_ref()?.passport_number.clone(),
        415 => bw.identity.as_ref()?.license_number.clone(),
        416 => bw.identity.as_ref()?.first_name.clone(),
        417 => bw.identity.as_ref()?.last_name.clone(),
        418 => bitwarden_identity_full_name(bw.identity.as_ref()?),
        _ => None,
    }
}

fn bitwarden_identity_full_name(id: &BwIdentity) -> Option<String> {
    let parts: Vec<&str> = [
        id.first_name.as_deref(),
        id.middle_name.as_deref(),
        id.last_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|s| !s.is_empty())
    .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn convert_password_history(history: Option<&[BwPasswordHistory]>) -> Vec<PasswordHistoryEntry> {
    history
        .unwrap_or_default()
        .iter()
        .filter(|h| !h.password.is_empty())
        .map(|h| PasswordHistoryEntry {
            password: h.password.clone(),
            changed_at: h.last_used_date.clone().unwrap_or_default(),
        })
        .collect()
}

fn convert_fido2_credentials(login: Option<&BwLogin>) -> Vec<Fido2Credential> {
    login
        .and_then(|l| l.fido2_credentials.as_deref())
        .map(|credentials| {
            credentials
                .iter()
                .filter(|c| !c.credential_id.is_empty() || !c.rp_id.is_empty())
                .map(|c| Fido2Credential {
                    credential_id: c.credential_id.clone(),
                    user_handle: c.user_handle.clone().unwrap_or_default(),
                    rp_id: c.rp_id.clone(),
                    rp_name: c.rp_name.clone().unwrap_or_default(),
                    user_name: c.user_name.clone().unwrap_or_default(),
                    user_display_name: c.user_display_name.clone().unwrap_or_default(),
                    // Bitwarden keyType/keyCurve have no target slot; the
                    // algorithm carries the relevant curve choice.
                    algorithm: c.key_algorithm.clone(),
                    private_key: c.key_value.clone(),
                    counter: c.counter.parse::<u32>().unwrap_or_default(),
                    discoverable: c.discoverable.eq_ignore_ascii_case("true"),
                    created_at: c.creation_date.clone().unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::ItemContent;

    use aes::cipher::BlockModeEncrypt;
    use cbc::Encryptor as CbcEncryptor;
    use rand_core::{OsRng, RngCore};

    type Aes256CbcEnc = CbcEncryptor<Aes256>;

    /// Build a Bitwarden-shaped encrypted string `2.iv|ct|mac` over a known
    /// (enc_key, mac_key) pair, used to round-trip the importer.
    fn make_enc_string(plaintext: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> String {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let mut buf = vec![0u8; plaintext.len() + 16];
        let cipher = Aes256CbcEnc::new(enc_key.into(), &iv.into());
        let ct_len = cipher
            .encrypt_padded_b2b::<Pkcs7>(plaintext, &mut buf)
            .expect("encrypt fits")
            .len();
        buf.truncate(ct_len);
        let mut hmac = HmacSha256::new_from_slice(mac_key).unwrap();
        hmac.update(&iv);
        hmac.update(&buf);
        let mac = hmac.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            B64.encode(iv),
            B64.encode(&buf),
            B64.encode(mac.as_slice()),
        )
    }

    fn fast_envelope(password: &[u8], inner_json: &str) -> Vec<u8> {
        // Use PBKDF2 with a very low iteration count so tests are quick.
        let salt = b"unit-test-salt".to_vec();
        let mut master = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, 1, &mut master);
        let (enc, mac) = stretch_keys(&master);
        let validation = make_enc_string(b"correct-password", &enc, &mac);
        let data = make_enc_string(inner_json.as_bytes(), &enc, &mac);
        let envelope = serde_json::json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": B64.encode(&salt),
            "kdfType": 0,
            "kdfIterations": 1,
            "encKeyValidation_DO_NOT_EDIT": validation,
            "data": data,
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn round_trips_a_login_item() {
        let inner = r#"{
            "items": [{
                "id": "abc",
                "name": "GitHub",
                "type": 1,
                "favorite": true,
                "notes": "sshkey backup",
                "login": {
                    "username": "alice",
                    "password": "hunter2",
                    "uris": [{ "uri": "https://github.com" }],
                    "totp": "JBSWY3DPEHPK3PXP",
                    "fido2Credentials": [{
                        "credentialId": "cred-1",
                        "keyAlgorithm": "ES256",
                        "keyValue": "private-key",
                        "rpId": "github.com",
                        "userHandle": "handle-1",
                        "userName": "alice",
                        "counter": "42",
                        "rpName": "GitHub",
                        "userDisplayName": "Alice",
                        "discoverable": "true",
                        "creationDate": "2026-01-01T00:00:00.000Z"
                    }]
                },
                "passwordHistory": [{
                    "password": "old-password",
                    "lastUsedDate": "2025-12-01T00:00:00.000Z"
                }],
                "fields": [
                    { "name": "API token", "value": "sk_live_x", "type": 1 },
                    { "name": "Linked password", "type": 3, "linkedId": 101 }
                ]
            }]
        }"#;
        let payload = fast_envelope(b"password", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"password").unwrap();
        assert_eq!(items.len(), 1);
        let item = &items[0];
        assert_eq!(item.title, "GitHub");
        assert!(item.favorite);
        match &item.content {
            ItemContent::Login(l) => {
                assert_eq!(l.username, "alice");
                assert_eq!(l.password, "hunter2");
                assert_eq!(l.urls.len(), 1);
                assert_eq!(l.urls[0].url, "https://github.com");
                assert_eq!(l.notes_text, "sshkey backup");
                assert_eq!(l.totp.as_ref().unwrap().secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(l.custom_fields.len(), 2);
                assert_eq!(l.custom_fields[0].name, "API token");
                assert_eq!(l.custom_fields[0].kind, CustomFieldKind::Concealed);
                assert_eq!(l.custom_fields[1].name, "Linked password");
                assert_eq!(l.custom_fields[1].value, "hunter2");
                assert_eq!(l.password_history.len(), 1);
                assert_eq!(l.password_history[0].password, "old-password");
                assert_eq!(l.password_history[0].changed_at, "2025-12-01T00:00:00.000Z");
                assert_eq!(l.fido2_credentials.len(), 1);
                assert_eq!(l.fido2_credentials[0].credential_id, "cred-1");
                assert_eq!(l.fido2_credentials[0].private_key, "private-key");
                assert_eq!(l.fido2_credentials[0].rp_id, "github.com");
                assert_eq!(l.fido2_credentials[0].counter, 42);
                assert!(l.fido2_credentials[0].discoverable);
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn accepts_null_password_history_from_export() {
        let inner = r#"{
            "items": [{
                "id": "abc",
                "name": "GitHub",
                "type": 1,
                "login": {
                    "username": "alice",
                    "password": "hunter2",
                    "fido2Credentials": []
                },
                "passwordHistory": null
            }]
        }"#;
        let payload = fast_envelope(b"password", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"password").unwrap();
        match &items[0].content {
            ItemContent::Login(l) => assert!(l.password_history.is_empty()),
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn null_password_history_and_fido2_do_not_reject() {
        // Bitwarden exports commonly write `"passwordHistory": null` and
        // omit or null `fido2Credentials`; both must parse to empty rather
        // than rejecting the whole export.
        let inner = r#"{
            "items": [{
                "id": "l1",
                "name": "GitHub",
                "type": 1,
                "login": { "username": "a", "password": "b", "fido2Credentials": null },
                "passwordHistory": null
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Login(l) => {
                assert!(l.password_history.is_empty());
                assert!(l.fido2_credentials.is_empty());
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn round_trips_a_secure_note() {
        let inner = r#"{
            "items": [{
                "id": "n1",
                "name": "Wifi",
                "type": 2,
                "notes": "ssid: home / pass: secret",
                "secureNote": { "type": 0 }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::SecureNote(n) => assert_eq!(n.body_text, "ssid: home / pass: secret"),
            _ => panic!("expected secure note"),
        }
    }

    #[test]
    fn wrong_password_fails_mac() {
        let inner = r#"{ "items": [] }"#;
        let payload = fast_envelope(b"good", inner);
        let err = import_bitwarden_encrypted_json(&payload, b"bad").unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn tampered_data_fails_mac() {
        let inner = r#"{ "items": [] }"#;
        let mut payload = fast_envelope(b"pw", inner);
        // Flip a single byte inside the `data` field. The envelope is JSON,
        // so flip the last byte of the file (which is `}`) - any change to
        // the payload outside the JSON envelope must surface as a parse
        // error or MAC failure, never a silent accept.
        let last = payload.len() - 2;
        payload[last] ^= 0x01;
        let err = import_bitwarden_encrypted_json(&payload, b"pw").unwrap_err();
        // Either MAC failure or import error; not a success.
        assert!(matches!(
            err,
            CryptoError::AuthFailure | CryptoError::Import(_)
        ));
    }

    #[test]
    fn unsupported_enc_string_type_rejected() {
        let inner = r#"{ "items": [] }"#;
        let mut payload = fast_envelope(b"pw", inner);
        // Find the first occurrence of `"data":"2.` and change to `"data":"9.`
        // so the encrypted-string type is unsupported.
        let key = b"\"data\":\"2.";
        if let Some(pos) = find(&payload, key) {
            payload[pos + key.len() - 2] = b'9';
        }
        let err = import_bitwarden_encrypted_json(&payload, b"pw").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::Import(_) | CryptoError::AuthFailure
        ));
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn rejects_unencrypted_export() {
        let inner = serde_json::json!({
            "encrypted": false,
            "salt": "",
            "encKeyValidation_DO_NOT_EDIT": "",
            "data": "",
        });
        let payload = serde_json::to_vec(&inner).unwrap();
        let err = import_bitwarden_encrypted_json(&payload, b"any").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn imports_unencrypted_json() {
        let payload = br#"{
            "encrypted": false,
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [{
                "id": "abc",
                "name": "GitHub",
                "type": 1,
                "favorite": true,
                "folderId": "f1",
                "login": {
                    "username": "alice",
                    "password": "hunter2",
                    "uris": [{ "uri": "https://github.com" }]
                }
            }]
        }"#;
        let items = import_bitwarden_json(payload).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "GitHub");
        assert_eq!(items[0].source_collection.as_deref(), Some("Work"));
        assert!(items[0].favorite);
        match &items[0].content {
            ItemContent::Login(login) => {
                assert_eq!(login.username, "alice");
                assert_eq!(login.password, "hunter2");
                assert_eq!(login.urls[0].url, "https://github.com");
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn plaintext_importer_rejects_encrypted_json() {
        let payload = fast_envelope(b"pw", r#"{ "items": [] }"#);
        let err = import_bitwarden_json(&payload).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_ciphertext_not_block_aligned() {
        // Construct a manually-crafted envelope where the ciphertext component
        // of the data field is not a multiple of 16 bytes. The decoder should
        // reject this before performing the HMAC check.
        let salt = b"unit-test-salt".to_vec();
        let mut master = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"pw", &salt, 1, &mut master);
        let (enc, mac) = stretch_keys(&master);
        let enc_ref: &[u8; 32] = &enc;
        let mac_ref: &[u8; 32] = &mac;
        // Valid validation field so we get past it.
        let validation = make_enc_string(b"v", enc_ref, mac_ref);
        // Build a malformed data field: 15-byte ciphertext.
        let iv = [0u8; 16];
        let bad_ct = vec![0u8; 15];
        let mut hmac = HmacSha256::new_from_slice(mac_ref).unwrap();
        hmac.update(&iv);
        hmac.update(&bad_ct);
        let tag = hmac.finalize().into_bytes();
        let data = format!(
            "2.{}|{}|{}",
            B64.encode(iv),
            B64.encode(&bad_ct),
            B64.encode(tag.as_slice())
        );
        let envelope = serde_json::json!({
            "encrypted": true,
            "salt": B64.encode(&salt),
            "kdfType": 0,
            "kdfIterations": 1,
            "encKeyValidation_DO_NOT_EDIT": validation,
            "data": data,
        });
        let payload = serde_json::to_vec(&envelope).unwrap();
        let err = import_bitwarden_encrypted_json(&payload, b"pw").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_excessive_pbkdf2_iterations_before_decrypting() {
        let envelope = serde_json::json!({
            "encrypted": true,
            "salt": B64.encode(b"salt"),
            "kdfType": 0,
            "kdfIterations": MAX_PBKDF2_ITERATIONS + 1,
            "encKeyValidation_DO_NOT_EDIT": "",
            "data": "",
        });
        let payload = serde_json::to_vec(&envelope).unwrap();
        let err = import_bitwarden_encrypted_json(&payload, b"pw").unwrap_err();
        assert!(matches!(err, CryptoError::Kdf(_)));
    }

    #[test]
    fn rejects_excessive_argon2_memory_before_deriving() {
        let envelope = serde_json::json!({
            "encrypted": true,
            "salt": B64.encode(b"salt"),
            "kdfType": 1,
            "kdfIterations": 3,
            "kdfMemory": MAX_ARGON2_MEMORY_MIB + 1,
            "kdfParallelism": 4,
            "encKeyValidation_DO_NOT_EDIT": "",
            "data": "",
        });
        let payload = serde_json::to_vec(&envelope).unwrap();
        let err = import_bitwarden_encrypted_json(&payload, b"pw").unwrap_err();
        assert!(matches!(err, CryptoError::Kdf(_)));
    }

    #[test]
    fn parses_otpauth_totp_field() {
        let inner = r#"{
            "items": [{
                "id": "abc",
                "name": "GitHub",
                "type": 1,
                "login": {
                    "username": "alice",
                    "password": "hunter2",
                    "totp": "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=45&digits=8"
                }
            }]
        }"#;
        let payload = fast_envelope(b"password", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"password").unwrap();
        match &items[0].content {
            ItemContent::Login(l) => {
                let totp = l.totp.as_ref().unwrap();
                assert_eq!(totp.secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(totp.period_seconds, 45);
                assert_eq!(totp.digits, 8);
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn preserves_folder_as_source_collection() {
        let inner = r#"{
            "folders": [{ "id": "f1", "name": "Work" }],
            "items": [{
                "id": "i1",
                "name": "Internal",
                "type": 1,
                "folderId": "f1",
                "login": { "username": "u", "password": "p" }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        assert_eq!(items[0].source_collection.as_deref(), Some("Work"));
    }

    #[test]
    fn maps_card_type_into_card_content() {
        let inner = r#"{
            "items": [{
                "id": "c1",
                "name": "Visa Personal",
                "type": 3,
                "card": {
                    "cardholderName": "Alice Example",
                    "brand": "Visa",
                    "number": "4242424242424242",
                    "expMonth": "5",
                    "expYear": "2030",
                    "code": "123"
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Card(card) => {
                assert_eq!(card.cardholder_name, "Alice Example");
                assert_eq!(card.brand, "Visa");
                assert_eq!(card.number, "4242424242424242");
                // Two-digit month padded; four-digit year truncated to two.
                assert_eq!(card.expiry, "05/30");
                assert_eq!(card.cvv, "123");
            }
            other => panic!("expected Card, got {other:?}"),
        }
    }

    #[test]
    fn maps_identity_type_with_government_ids_and_address() {
        let inner = r#"{
            "items": [{
                "id": "id1",
                "name": "Personal",
                "type": 4,
                "identity": {
                    "firstName": "Alice",
                    "lastName": "Example",
                    "email": "alice@example.com",
                    "phone": "+1-555-0100",
                    "address1": "1 Test Way",
                    "address2": "Apt 2",
                    "city": "Springfield",
                    "state": "IL",
                    "postalCode": "62701",
                    "country": "USA",
                    "passportNumber": "P00000000",
                    "ssn": "000-00-0000",
                    "username": "alice42",
                    "title": "Ms"
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Identity(id) => {
                assert_eq!(id.first_name, "Alice");
                assert_eq!(id.last_name, "Example");
                assert_eq!(id.emails[0].value, "alice@example.com");
                let addr = id.addresses.first().expect("address mapped");
                assert_eq!(addr.street, "1 Test Way, Apt 2");
                assert_eq!(addr.city, "Springfield");
                assert_eq!(addr.region, "IL");
                assert_eq!(addr.postal_code, "62701");
                assert_eq!(addr.country, "USA");
                // Two government ids: passport + SSN. License missing -> skipped.
                let labels: Vec<&str> =
                    id.government_ids.iter().map(|g| g.label.as_str()).collect();
                assert!(labels.contains(&"Passport number"));
                assert!(labels.contains(&"Social Security Number"));
                assert!(!labels.contains(&"License number"));
                // Bitwarden's username / company / title now land in the
                // first-class IdentityContent slots rather than custom_fields.
                // The Bitwarden Identity in this fixture supplies a username,
                // title, and company - all three should be promoted.
                assert!(!id.username.is_empty());
                assert!(!id.job_title.is_empty());
            }
            other => panic!("expected Identity, got {other:?}"),
        }
    }

    #[test]
    fn maps_ssh_key_type_when_subobject_is_present() {
        let inner = r#"{
            "items": [{
                "id": "k1",
                "name": "Prod deploy",
                "type": 5,
                "sshKey": {
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA",
                    "publicKey": "ssh-ed25519 AAAA prod",
                    "keyFingerprint": "SHA256:abc"
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::SshKey(k) => {
                assert!(k.private_key.starts_with("-----BEGIN OPENSSH"));
                assert_eq!(k.public_key, "ssh-ed25519 AAAA prod");
                assert_eq!(k.fingerprint, "SHA256:abc");
            }
            other => panic!("expected SshKey, got {other:?}"),
        }
    }

    #[test]
    fn ssh_key_type_without_subobject_falls_back_to_passthrough() {
        // Older Bitwarden builds reported type 5 without the dedicated
        // sshKey subobject. The importer must not panic; it falls back to
        // ApiCredential passthrough so the raw fields are preserved.
        let inner = r#"{
            "items": [{
                "id": "k2",
                "name": "Legacy ssh",
                "type": 5
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        assert!(matches!(items[0].content, ItemContent::ApiCredential(_)));
    }

    #[test]
    fn uri_match_default_strategy_carries_no_hint() {
        // Bitwarden's `match: 0` means "use the user's globally-configured
        // default match strategy". The factory default is Host, but a user
        // may have changed it. Mapping 0 -> None preserves that semantics
        // so the destination client applies its own default rather than
        // fabricating a hint that may not match the source vault.
        let inner = r#"{
            "items": [{
                "id": "u1",
                "name": "Default match",
                "type": 1,
                "login": {
                    "username": "u",
                    "password": "p",
                    "uris": [
                        { "uri": "https://example.com",      "match": 0 },
                        { "uri": "https://exact.example.com","match": 3 }
                    ]
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Login(l) => {
                assert_eq!(l.urls.len(), 2);
                assert!(l.urls[0].match_type.is_none(), "default (0) stays None");
                assert_eq!(l.urls[1].match_type, Some(UrlMatchType::Exact));
            }
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn unknown_uri_match_strategy_carries_no_hint() {
        // Future Bitwarden builds may add new match strategies past 5. The
        // importer must fall through to None rather than panic or guess.
        let inner = r#"{
            "items": [{
                "id": "u2",
                "name": "Unknown match",
                "type": 1,
                "login": {
                    "username": "u",
                    "password": "p",
                    "uris": [{ "uri": "https://example.com", "match": 99 }]
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Login(l) => assert!(l.urls[0].match_type.is_none()),
            _ => panic!("expected Login"),
        }
    }

    #[test]
    fn card_with_all_fields_empty_still_maps_to_card_content() {
        // A Bitwarden card row with the `card` subobject present but every
        // field null/missing must not panic and must still produce a Card
        // (not silently downgrade to passthrough). All slots end up empty
        // and `expiry` collapses to "" rather than rendering as "//".
        let inner = r#"{
            "items": [{
                "id": "c0",
                "name": "Empty card",
                "type": 3,
                "card": {}
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Card(card) => {
                assert_eq!(card.cardholder_name, "");
                assert_eq!(card.number, "");
                assert_eq!(card.brand, "");
                assert_eq!(card.expiry, "");
                assert_eq!(card.cvv, "");
                assert_eq!(card.pin, "");
            }
            other => panic!("expected Card, got {other:?}"),
        }
    }

    #[test]
    fn identity_without_address_components_leaves_address_none() {
        // When every address line plus city/state/zip/country is empty or
        // missing, `address` must be None rather than Some(PostalAddress{..
        // empty strings ..}). Other identity slots still populate.
        let inner = r#"{
            "items": [{
                "id": "id0",
                "name": "No address",
                "type": 4,
                "identity": {
                    "firstName": "Alice",
                    "lastName": "Example"
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Identity(id) => {
                assert_eq!(id.first_name, "Alice");
                assert!(
                    id.addresses.is_empty(),
                    "addresses stays empty when all parts empty"
                );
                assert!(id.government_ids.is_empty());
            }
            other => panic!("expected Identity, got {other:?}"),
        }
    }

    #[test]
    fn identity_address_skips_blank_lines_without_leading_separator() {
        // address1 empty but address2/address3 populated must not produce
        // a leading ", " in the joined street. The filter on empty
        // components has to run before the join.
        let inner = r#"{
            "items": [{
                "id": "id1",
                "name": "Sparse address",
                "type": 4,
                "identity": {
                    "address1": "",
                    "address2": "Suite 200",
                    "address3": "PO Box 9",
                    "city": "Springfield"
                }
            }]
        }"#;
        let payload = fast_envelope(b"pw", inner);
        let items = import_bitwarden_encrypted_json(&payload, b"pw").unwrap();
        match &items[0].content {
            ItemContent::Identity(id) => {
                let addr = id.addresses.first().expect("address mapped");
                assert_eq!(addr.street, "Suite 200, PO Box 9");
                assert!(!addr.street.starts_with(", "));
            }
            other => panic!("expected Identity, got {other:?}"),
        }
    }

    #[test]
    fn card_expiry_does_not_panic_on_multibyte_year() {
        // A 4-byte UTF-8 codepoint has len() == 4 but no char boundary at
        // byte offset 2; slicing &y[2..] would panic. Such a year is passed
        // through whole instead.
        let expiry = format_card_expiry(Some("12"), Some("\u{1F600}"));
        assert_eq!(expiry, "12/\u{1F600}");
    }

    #[test]
    fn card_expiry_truncates_four_digit_year() {
        assert_eq!(format_card_expiry(Some("12"), Some("2026")), "12/26");
        assert_eq!(format_card_expiry(Some("3"), Some("27")), "03/27");
        assert_eq!(format_card_expiry(None, None), "");
    }

    #[test]
    fn bitwarden_totp_rejects_non_base32() {
        // A raw (non-otpauth) secret that is not valid base32 is dropped
        // rather than stored as a TOTP that would later emit wrong codes.
        assert!(bitwarden_totp("not base 32!").is_none());
    }

    #[test]
    fn bitwarden_totp_accepts_valid_base32() {
        let totp = bitwarden_totp("jbswy3dpehpk3pxp").expect("valid base32 secret");
        assert_eq!(totp.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.digits, 6);
    }
}

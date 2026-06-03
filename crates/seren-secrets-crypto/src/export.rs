//! Encrypted JSON backup format.
//!
//! Wire shape of the backup file:
//!
//!   {
//!     "format": "seren-secrets-backup",
//!     "version": 1,
//!     "kdf": { ... KdfParams ... },
//!     "ciphertext_b64": "..."   // AEAD blob over the inner BackupBody
//!   }
//!
//! `ciphertext_b64` is an XChaCha20-Poly1305 envelope from this crate's `aead`
//! module, keyed by an Argon2id-derived key over the user's passphrase. The
//! inner plaintext is JSON of `BackupBody`, which carries the full set of
//! decrypted items the user chose to export (typically every item across every
//! vault the caller can decrypt).
//!
//! The format is documented as the canonical Seren Secrets backup file and
//! is the inverse operation of `import_backup`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::aead::{xchacha20_decrypt, xchacha20_encrypt};
use crate::error::{CryptoError, CryptoResult};
use crate::kdf::{KdfParams, default_params, derive_key};
use crate::protocol::item::ItemContent;

pub const BACKUP_FORMAT: &str = "seren-secrets-backup";
pub const BACKUP_VERSION: u8 = 1;

/// Upper bound on KDF cost accepted from a backup envelope.
/// 1 GiB memory is above any reasonable Argon2id deployment.
const MAX_DECRYPT_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_DECRYPT_TIME_COST: u32 = 32;
const MAX_DECRYPT_PARALLELISM: u32 = 64;
/// Backup encryption uses a fixed 32-byte AEAD key. Any other value indicates
/// a tampered or malformed envelope; reject before doing expensive work.
const REQUIRED_KEY_LEN: u32 = 32;
const MAX_SALT_LEN: usize = 1024;
/// Decoded ciphertext allocation cap for untrusted backup envelopes.
const MAX_CIPHERTEXT_DECODED_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub format: String,
    pub version: u8,
    pub kdf: KdfParams,
    pub ciphertext_b64: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupBody {
    pub items: Vec<BackupItem>,
    /// RFC3339 export timestamp.
    pub exported_at: String,
    /// Free-form metadata the caller may use (vault names, source identity).
    pub metadata: serde_json::Value,
}

impl std::fmt::Debug for BackupBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupBody")
            .field("items_len", &self.items.len())
            .field("exported_at", &self.exported_at)
            .field("metadata", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupItem {
    /// User-visible title (decrypted at export time; encrypted again when imported).
    pub title: String,
    pub content: ItemContent,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Optional vault name to help the importer place items in the right place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_vault: Option<String>,
}

impl std::fmt::Debug for BackupItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupItem")
            .field("title", &"<redacted>")
            .field("content", &self.content)
            .field("tags_len", &self.tags.len())
            .field("favorite", &self.favorite)
            .field("source_vault", &"<redacted>")
            .finish()
    }
}

/// Encrypt `body` under a passphrase, returning a fully-formed backup file.
pub fn encrypt_backup(passphrase: &[u8], body: &BackupBody) -> CryptoResult<BackupEnvelope> {
    let kdf = default_params();
    let key_bytes = derive_key(passphrase, &kdf)?;
    if key_bytes.len() != 32 {
        return Err(CryptoError::Export("kdf produced wrong key length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let plaintext = serde_json::to_vec(body).map_err(|_| CryptoError::Export("body json"))?;
    let ct = xchacha20_encrypt(&key, &plaintext);

    Ok(BackupEnvelope {
        format: BACKUP_FORMAT.to_string(),
        version: BACKUP_VERSION,
        kdf,
        ciphertext_b64: B64.encode(ct),
    })
}

/// Decrypt a backup envelope using a passphrase.
pub fn decrypt_backup(passphrase: &[u8], envelope: &BackupEnvelope) -> CryptoResult<BackupBody> {
    decrypt_backup_inner(passphrase, envelope, MAX_CIPHERTEXT_DECODED_BYTES)
}

fn decrypt_backup_inner(
    passphrase: &[u8],
    envelope: &BackupEnvelope,
    max_decoded_bytes: usize,
) -> CryptoResult<BackupBody> {
    if envelope.format != BACKUP_FORMAT {
        return Err(CryptoError::Import("backup format mismatch"));
    }
    if envelope.version != BACKUP_VERSION {
        return Err(CryptoError::Import("unsupported backup version"));
    }
    // Validate envelope-supplied KDF params before doing any expensive work.
    validate_decrypt_kdf(&envelope.kdf)?;
    // Reject impossible-to-fit base64 before allocating the decoded buffer.
    if envelope.ciphertext_b64.len() > max_decoded_bytes / 3 * 4 {
        return Err(CryptoError::Import("backup ciphertext too large"));
    }
    let ct = B64
        .decode(envelope.ciphertext_b64.as_bytes())
        .map_err(|_| CryptoError::Import("ciphertext base64"))?;
    let key_bytes = derive_key(passphrase, &envelope.kdf)?;
    if key_bytes.len() != 32 {
        return Err(CryptoError::Import("kdf produced wrong key length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let pt = xchacha20_decrypt(&key, &ct)?;
    let body: BackupBody =
        serde_json::from_slice(&pt).map_err(|_| CryptoError::Import("body json"))?;
    Ok(body)
}

fn validate_decrypt_kdf(kdf: &KdfParams) -> CryptoResult<()> {
    if kdf.output_len != REQUIRED_KEY_LEN {
        return Err(CryptoError::Import("backup kdf output_len must be 32"));
    }
    if kdf.memory_kib > MAX_DECRYPT_MEMORY_KIB {
        return Err(CryptoError::Import("backup kdf memory_kib too large"));
    }
    if kdf.time_cost > MAX_DECRYPT_TIME_COST {
        return Err(CryptoError::Import("backup kdf time_cost too large"));
    }
    if kdf.parallelism == 0 || kdf.parallelism > MAX_DECRYPT_PARALLELISM {
        return Err(CryptoError::Import("backup kdf parallelism out of range"));
    }
    if kdf.salt.len() > MAX_SALT_LEN {
        return Err(CryptoError::Import("backup kdf salt too long"));
    }
    Ok(())
}

/// Convenience: serialize the envelope to JSON.
pub fn envelope_to_json(envelope: &BackupEnvelope) -> CryptoResult<String> {
    serde_json::to_string_pretty(envelope).map_err(|_| CryptoError::Export("envelope json"))
}

/// Convenience: parse the envelope from JSON.
pub fn envelope_from_json(s: &str) -> CryptoResult<BackupEnvelope> {
    serde_json::from_str(s).map_err(|_| CryptoError::Import("envelope json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfAlgorithm;
    use crate::protocol::item::LoginContent;

    fn fast_envelope(body: &BackupBody, pw: &[u8]) -> BackupEnvelope {
        let fast_kdf = KdfParams {
            version: 1,
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 8,
            time_cost: 1,
            parallelism: 1,
            output_len: 32,
            salt: vec![0xAB; 16],
        };
        let key_bytes = derive_key(pw, &fast_kdf).unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let plaintext = serde_json::to_vec(body).unwrap();
        let ct = xchacha20_encrypt(&key, &plaintext);
        BackupEnvelope {
            format: BACKUP_FORMAT.to_string(),
            version: BACKUP_VERSION,
            kdf: fast_kdf,
            ciphertext_b64: B64.encode(ct),
        }
    }

    fn sample_body() -> BackupBody {
        BackupBody {
            items: vec![BackupItem {
                title: "Example".into(),
                content: ItemContent::Login(LoginContent {
                    username: "alice".into(),
                    password: "hunter2".into(),
                    urls: vec!["https://example.com".into()],
                    totp: None,
                    notes: crate::prose::ProseDoc::empty(),
                    notes_text: String::new(),
                    custom_fields: Vec::new(),
                    password_history: Vec::new(),
                    raw_import: serde_json::Value::Null,
                    ..Default::default()
                }),
                tags: vec!["test".into()],
                favorite: true,
                source_vault: Some("Personal".into()),
            }],
            exported_at: "2026-05-21T12:00:00Z".into(),
            metadata: serde_json::json!({ "source": "unit-test" }),
        }
    }

    #[test]
    fn round_trip() {
        let body = sample_body();
        let envelope = fast_envelope(&body, b"hunter2");
        let recovered = decrypt_backup(b"hunter2", &envelope).unwrap();
        assert_eq!(recovered, body);
    }

    #[test]
    fn debug_redacts_decrypted_backup_plaintext() {
        let rendered = format!("{:?}", sample_body());
        for secret in ["Example", "hunter2", "Personal", "unit-test", "test"] {
            assert!(
                !rendered.contains(secret),
                "BackupBody Debug leaked plaintext {secret}: {rendered}"
            );
        }
        assert!(rendered.contains("metadata: \"<redacted>\""));
        assert!(rendered.contains("items_len"));
    }

    #[test]
    fn wrong_passphrase_fails() {
        let body = sample_body();
        let envelope = fast_envelope(&body, b"good");
        let err = decrypt_backup(b"bad", &envelope).unwrap_err();
        assert!(matches!(err, CryptoError::AuthFailure));
    }

    #[test]
    fn envelope_json_round_trip() {
        let body = sample_body();
        let envelope = fast_envelope(&body, b"x");
        let s = envelope_to_json(&envelope).unwrap();
        let parsed = envelope_from_json(&s).unwrap();
        assert_eq!(envelope.format, parsed.format);
        assert_eq!(envelope.version, parsed.version);
        assert_eq!(envelope.ciphertext_b64, parsed.ciphertext_b64);
    }

    #[test]
    fn rejects_wrong_format() {
        let body = sample_body();
        let mut envelope = fast_envelope(&body, b"x");
        envelope.format = "other".into();
        let err = decrypt_backup(b"x", &envelope).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_wrong_version() {
        let body = sample_body();
        let mut envelope = fast_envelope(&body, b"x");
        envelope.version = 99;
        let err = decrypt_backup(b"x", &envelope).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_oversized_kdf_memory() {
        let body = sample_body();
        let mut envelope = fast_envelope(&body, b"x");
        envelope.kdf.memory_kib = u32::MAX;
        let err = decrypt_backup(b"x", &envelope).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_oversized_kdf_output_len() {
        let body = sample_body();
        let mut envelope = fast_envelope(&body, b"x");
        envelope.kdf.output_len = 1 << 20;
        let err = decrypt_backup(b"x", &envelope).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let body = sample_body();
        let mut envelope = fast_envelope(&body, b"x");
        envelope.ciphertext_b64.truncate(4);
        let err = decrypt_backup(b"x", &envelope).unwrap_err();
        // Could be base64 error or AEAD error depending on truncation; both are Import/AuthFailure.
        assert!(matches!(
            err,
            CryptoError::Import(_) | CryptoError::AuthFailure | CryptoError::InvalidCiphertext
        ));
    }

    #[test]
    fn rejects_malformed_envelope_json() {
        let err = envelope_from_json("not json at all").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_oversized_ciphertext() {
        let body = sample_body();
        let envelope = fast_envelope(&body, b"x");
        let err = decrypt_backup_inner(b"x", &envelope, 8).unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
        let ok = decrypt_backup_inner(b"x", &envelope, MAX_CIPHERTEXT_DECODED_BYTES).unwrap();
        assert_eq!(ok, body);
    }
}

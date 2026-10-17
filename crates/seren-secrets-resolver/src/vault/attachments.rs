//! Existing Passwords attachment wire protocol; plaintext stays in memory.

use super::*;
use seren_secrets_crypto::protocol::attachment;

const MAX_ENCRYPTED_BYTES: usize = 100 * 1024 * 1024;
const MAX_ITEM_ENCRYPTED_BYTES: u64 = 500 * 1024 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
// The shared AEAD format has two version bytes, a 24-byte nonce and a 16-byte tag.
const ENVELOPE_BYTES: usize = 2 + 24 + 16;
pub const MAX_ATTACHMENT_PLAINTEXT_BYTES: usize = MAX_ENCRYPTED_BYTES - ENVELOPE_BYTES;
const fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}
const MAX_DOWNLOAD_RESPONSE_BYTES: usize =
    base64_len(MAX_ENCRYPTED_BYTES) + 3 * base64_len(MAX_METADATA_BYTES) + 64 * 1024;

/// Owned upload; plaintext is wiped before the request is sent, including on error.
/// Deliberately has no Debug implementation.
pub struct AttachmentUpload {
    pub filename: Zeroizing<String>,
    pub content_type: Zeroizing<String>,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// Decrypted metadata. Never log this view; names are zeroized on drop.
pub struct AttachmentSummary {
    pub attachment_id: Uuid,
    pub item_id: Uuid,
    pub filename: Zeroizing<String>,
    pub content_type: Zeroizing<String>,
    /// Plaintext byte count; the service stores the encrypted size instead.
    pub size_bytes: u64,
    pub encrypted_size_bytes: u64,
    pub created_at: Timestamp,
}

/// Downloaded plaintext, wiped on drop. Deliberately has no Debug implementation.
pub struct DecryptedAttachment {
    pub summary: AttachmentSummary,
    pub bytes: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
struct AttachmentRecord {
    attachment_id: Uuid,
    item_id: Uuid,
    filename_ciphertext: String,
    content_type_ciphertext: String,
    wrapped_content_key: String,
    size_bytes: i64,
    created_at: String,
}

#[derive(Deserialize)]
struct AttachmentWithBlob {
    #[serde(flatten)]
    record: AttachmentRecord,
    blob: String,
}

fn bounded_decode(encoded: &str, limit: usize) -> Result<Vec<u8>, ResolverError> {
    if encoded.len() > base64_len(limit) {
        return Err(ResolverError::Malformed("attachment size"));
    }
    let decoded = b64_decode(encoded, "attachment encoding")?;
    if decoded.len() > limit {
        return Err(ResolverError::Malformed("attachment size"));
    }
    Ok(decoded)
}

fn attachment_summary(
    vault_key: &VaultKey,
    item_id: Uuid,
    record: &AttachmentRecord,
) -> Result<AttachmentSummary, ResolverError> {
    if record.item_id != item_id {
        return Err(ResolverError::ResponseMismatch);
    }
    let size = usize::try_from(record.size_bytes)
        .map_err(|_| ResolverError::Malformed("attachment size"))?;
    if !(ENVELOPE_BYTES + 1..=MAX_ENCRYPTED_BYTES).contains(&size) {
        return Err(ResolverError::Malformed("attachment size"));
    }
    let id = record.attachment_id.as_bytes();
    // Verify every field's AAD, including the wrapped key on metadata-only reads.
    let _key = attachment::unwrap_attachment_key(
        vault_key,
        item_id.as_bytes(),
        id,
        &bounded_decode(&record.wrapped_content_key, MAX_METADATA_BYTES)?,
    )?;
    let filename = Zeroizing::new(attachment::decrypt_filename(
        vault_key,
        item_id.as_bytes(),
        id,
        &bounded_decode(&record.filename_ciphertext, MAX_METADATA_BYTES)?,
    )?);
    let content_type = Zeroizing::new(attachment::decrypt_content_type(
        vault_key,
        item_id.as_bytes(),
        id,
        &bounded_decode(&record.content_type_ciphertext, MAX_METADATA_BYTES)?,
    )?);
    Ok(AttachmentSummary {
        attachment_id: record.attachment_id,
        item_id,
        filename,
        content_type,
        size_bytes: (size - ENVELOPE_BYTES) as u64,
        encrypted_size_bytes: size as u64,
        created_at: record
            .created_at
            .parse()
            .map_err(|_| ResolverError::Malformed("attachment created_at"))?,
    })
}

fn build_attachment_request(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment_id: Uuid,
    upload: AttachmentUpload,
) -> Result<serde_json::Value, ResolverError> {
    if upload.bytes.is_empty()
        || upload.bytes.len() > MAX_ATTACHMENT_PLAINTEXT_BYTES
        || upload.filename.is_empty()
        || upload.filename.len() > MAX_METADATA_BYTES - ENVELOPE_BYTES
        || upload.content_type.is_empty()
        || upload.content_type.len() > MAX_METADATA_BYTES - ENVELOPE_BYTES
    {
        return Err(ResolverError::InvalidInput("attachment size"));
    }
    let key = attachment::generate_attachment_key();
    let item = item_id.as_bytes();
    let id = attachment_id.as_bytes();
    // Both the owned plaintext and the random attachment key drop here, before I/O.
    Ok(serde_json::json!({
        "attachment_id": attachment_id,
        "blob": B64.encode(attachment::encrypt_blob(&key, item, id, &upload.bytes)),
        "filename_ciphertext": B64.encode(attachment::encrypt_filename(vault_key, item, id, &upload.filename)),
        "content_type_ciphertext": B64.encode(attachment::encrypt_content_type(vault_key, item, id, &upload.content_type)),
        "wrapped_content_key": B64.encode(attachment::wrap_attachment_key(vault_key, item, id, &key)),
    }))
}

impl VaultClient {
    /// List attachment metadata using the existing read/approval route, without blobs.
    pub async fn list_attachments(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<Vec<AttachmentSummary>, ResolverError> {
        let value = self
            .call(
                reqwest::Method::GET,
                &format!("/vaults/{vault_id}/items/{item_id}/attachments"),
                None,
            )
            .await?;
        let records: Vec<AttachmentRecord> = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("attachment list"))?;
        let mut seen = std::collections::HashSet::new();
        let mut total = 0u64;
        records
            .iter()
            .map(|record| {
                if !seen.insert(record.attachment_id) {
                    return Err(ResolverError::ResponseMismatch);
                }
                let summary = attachment_summary(vault_key, item_id, record)?;
                total = total
                    .checked_add(summary.encrypted_size_bytes)
                    .ok_or(ResolverError::Malformed("attachment total size"))?;
                if total > MAX_ITEM_ENCRYPTED_BYTES {
                    return Err(ResolverError::Malformed("attachment total size"));
                }
                Ok(summary)
            })
            .collect()
    }

    /// Download/decrypt with the existing per-attachment key and both UUIDs in AAD.
    pub async fn get_attachment(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        attachment_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<DecryptedAttachment, ResolverError> {
        let value = self
            .call_with_options(
                reqwest::Method::GET,
                &format!("/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}"),
                None,
                None,
                MAX_DOWNLOAD_RESPONSE_BYTES,
            )
            .await?;
        let response: AttachmentWithBlob = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("attachment record"))?;
        if response.record.attachment_id != attachment_id {
            return Err(ResolverError::ResponseMismatch);
        }
        let summary = attachment_summary(vault_key, item_id, &response.record)?;
        let blob = bounded_decode(&response.blob, MAX_ENCRYPTED_BYTES)?;
        if blob.len() as u64 != summary.encrypted_size_bytes {
            return Err(ResolverError::Malformed("attachment blob size"));
        }
        let key = attachment::unwrap_attachment_key(
            vault_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &bounded_decode(&response.record.wrapped_content_key, MAX_METADATA_BYTES)?,
        )?;
        let bytes = Zeroizing::new(attachment::decrypt_blob(
            &key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &blob,
        )?);
        if bytes.len() as u64 != summary.size_bytes {
            return Err(ResolverError::Malformed("attachment plaintext size"));
        }
        Ok(DecryptedAttachment { summary, bytes })
    }

    /// Encrypt/upload a fresh attachment. The service atomically enforces the
    /// 500 MiB per-item aggregate cap; this client enforces per-field/blob caps.
    pub async fn put_attachment(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        vault_key: &VaultKey,
        upload: AttachmentUpload,
    ) -> Result<AttachmentSummary, ResolverError> {
        let attachment_id = Uuid::new_v4();
        let expected_size = (upload.bytes.len() + ENVELOPE_BYTES) as u64;
        let body = build_attachment_request(vault_key, item_id, attachment_id, upload)?;
        let value = self
            .call(
                reqwest::Method::POST,
                &format!("/vaults/{vault_id}/items/{item_id}/attachments"),
                Some(body),
            )
            .await
            .map_err(item_write_error)?;
        let record: AttachmentRecord = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("created attachment"))?;
        if record.attachment_id != attachment_id {
            return Err(ResolverError::ResponseMismatch);
        }
        let summary = attachment_summary(vault_key, item_id, &record)?;
        if summary.encrypted_size_bytes != expected_size {
            return Err(ResolverError::Malformed("created attachment size"));
        }
        Ok(summary)
    }

    /// Delete only the named attachment, never its parent item.
    pub async fn delete_attachment(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<(), ResolverError> {
        self.call(
            reqwest::Method::DELETE,
            &format!("/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}"),
            None,
        )
        .await
        .map_err(item_write_error)?;
        Ok(())
    }
}

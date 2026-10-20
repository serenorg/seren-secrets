//! Existing Passwords attachment wire protocol; plaintext stays in memory.
//!
//! Guarded writes carry a caller-chosen id, the file's
//! SHA-256 sealed under the attachment key, the parent item's revision as a
//! weak `If-Match`, and a delete that names the exact stored digest
//! ciphertext. The service checks the guards in the write's transaction.

use super::*;
use crate::error::is_coded_server_error;
use seren_secrets_crypto::protocol::attachment;

pub const MAX_ENCRYPTED_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_ITEM_ENCRYPTED_BYTES: u64 = 500 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
// The shared AEAD format has two version bytes, a 24-byte nonce and a 16-byte tag.
pub const ENVELOPE_BYTES: usize = 2 + 24 + 16;
pub const MAX_ATTACHMENT_PLAINTEXT_BYTES: usize = MAX_ENCRYPTED_BYTES - ENVELOPE_BYTES;
const fn base64_len(bytes: usize) -> usize {
    bytes.div_ceil(3) * 4
}
pub const MAX_DOWNLOAD_RESPONSE_BYTES: usize =
    base64_len(MAX_ENCRYPTED_BYTES) + 3 * base64_len(MAX_METADATA_BYTES) + 64 * 1024;

/// Owned upload; plaintext is wiped before the request is sent, including on error.
/// Debug output is redacted.
pub struct AttachmentUpload {
    pub filename: Zeroizing<String>,
    pub content_type: Zeroizing<String>,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for AttachmentUpload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttachmentUpload([redacted])")
    }
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
    /// SHA-256 of the plaintext, opened from the stored digest. `None` when
    /// none was stored or it does not open: unverifiable, never a match.
    pub sha256: Option<[u8; 32]>,
}

/// Downloaded plaintext, wiped on drop. Deliberately has no Debug implementation.
pub struct DecryptedAttachment {
    pub summary: AttachmentSummary,
    pub bytes: Zeroizing<Vec<u8>>,
}

/// Outcome of [`VaultClient::put_attachment_with_id`].
pub enum AttachmentPutOutcome {
    /// The service stored this upload.
    Created(AttachmentSummary),
    /// The item already has this id for a file with the same SHA-256, name
    /// and size.
    AlreadyPresent,
    /// The item has this id for a different or unverifiable file, or another
    /// item uses the id.
    IdConflict,
    /// The parent item is no longer at the supplied revision; nothing was
    /// written.
    Stale,
}

/// Outcome of [`VaultClient::conditional_delete_attachment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentDeleteOutcome {
    Deleted,
    /// The item has no attachment with this id; nothing changed.
    AlreadyAbsent,
    /// The attachment holds a different, unverifiable or missing digest;
    /// nothing was deleted.
    Mismatch,
    /// The parent item is no longer at the supplied revision; nothing was
    /// deleted.
    Stale,
}

/// A guarded attachment write's outcome. Attachment writes never change the
/// parent item's `updated_at`.
#[derive(Debug)]
pub struct AttachmentWrite<T> {
    pub outcome: T,
    /// The parent item's `updated_at` as the service confirmed it under the
    /// item lock: from the response on success, and the sent revision on a
    /// 409, which the service answers only after that revision matched.
    /// `None` only for `Stale`, because the refusal does not report the
    /// current revision.
    pub item_updated_at: Option<Timestamp>,
}

#[derive(Deserialize)]
pub struct AttachmentRecord {
    pub attachment_id: Uuid,
    pub item_id: Uuid,
    pub filename_ciphertext: String,
    pub content_type_ciphertext: String,
    pub wrapped_content_key: String,
    pub size_bytes: i64,
    pub created_at: String,
    /// Null for uploads without a digest; absent from older services.
    #[serde(default)]
    pub digest_ciphertext: Option<String>,
}

#[derive(Deserialize)]
struct AttachmentWithBlob {
    #[serde(flatten)]
    record: AttachmentRecord,
    blob: String,
}

#[derive(Deserialize)]
struct CreatedAttachment {
    #[serde(flatten)]
    record: AttachmentRecord,
    item_updated_at: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConditionalDeleteState {
    Deleted,
    AlreadyAbsent,
}

#[derive(Deserialize)]
struct ConditionalDeleteResponse {
    state: ConditionalDeleteState,
    item_updated_at: String,
}

fn parse_item_updated_at(value: &str) -> Result<Timestamp, ResolverError> {
    value
        .parse()
        .map_err(|_| ResolverError::Malformed("attachment item_updated_at"))
}

pub fn bounded_decode(encoded: &str, limit: usize) -> Result<Vec<u8>, ResolverError> {
    if encoded.len() > base64_len(limit) {
        return Err(ResolverError::Malformed("attachment size"));
    }
    let decoded = b64_decode(encoded, "attachment encoding")?;
    if decoded.len() > limit {
        return Err(ResolverError::Malformed("attachment size"));
    }
    Ok(decoded)
}

pub fn attachment_summary(
    vault_key: &VaultKey,
    item_id: Uuid,
    record: &AttachmentRecord,
) -> Result<AttachmentSummary, ResolverError> {
    if record.item_id != item_id {
        return Err(ResolverError::ResponseMismatch);
    }
    let size = encrypted_size(record.size_bytes)? as usize;
    let id = record.attachment_id.as_bytes();
    // Verify every field's AAD, including the wrapped key on metadata-only reads.
    let key = attachment::unwrap_attachment_key(
        vault_key,
        item_id.as_bytes(),
        id,
        &bounded_decode(&record.wrapped_content_key, MAX_METADATA_BYTES)?,
    )?;
    // A digest that is missing or does not open is unverifiable, not an error,
    // so reading digests never makes a listing fail.
    let sha256 = record.digest_ciphertext.as_deref().and_then(|encoded| {
        let ciphertext = bounded_decode(encoded, MAX_METADATA_BYTES).ok()?;
        attachment::decrypt_digest(&key, item_id.as_bytes(), id, &ciphertext).ok()
    });
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
        sha256,
    })
}

/// Validate upload field limits and the encrypted per-item aggregate.
pub fn validate_upload(
    bytes: usize,
    filename: usize,
    content_type: usize,
    total: u64,
) -> Result<(), ResolverError> {
    if bytes == 0
        || bytes > MAX_ATTACHMENT_PLAINTEXT_BYTES
        || filename == 0
        || filename > MAX_METADATA_BYTES - ENVELOPE_BYTES
        || content_type == 0
        || content_type > MAX_METADATA_BYTES - ENVELOPE_BYTES
        || total
            .checked_add(bytes as u64 + ENVELOPE_BYTES as u64)
            .is_none_or(|total| total > MAX_ITEM_ENCRYPTED_BYTES)
    {
        return Err(ResolverError::InvalidInput("attachment size"));
    }
    Ok(())
}

/// Validate the service's encrypted byte count before allocating or decrypting.
pub fn encrypted_size(size: i64) -> Result<u64, ResolverError> {
    let size = u64::try_from(size).map_err(|_| ResolverError::Malformed("attachment size"))?;
    if size <= ENVELOPE_BYTES as u64 || size > MAX_ENCRYPTED_BYTES as u64 {
        return Err(ResolverError::Malformed("attachment size"));
    }
    Ok(size)
}

/// Encrypted create payload; no plaintext or unwrapped key is retained.
#[derive(Serialize)]
pub struct AttachmentRequest {
    pub attachment_id: Uuid,
    pub blob: String,
    pub filename_ciphertext: String,
    pub content_type_ciphertext: String,
    pub wrapped_content_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_ciphertext: Option<String>,
}

/// A short-lived upload preparation. Hosts can perform bulk encryption outside
/// their lock/session mutex; dropping it wipes the plaintext and attachment key.
pub struct PendingAttachmentUpload {
    request: AttachmentRequest,
    key: seren_secrets_crypto::keys::AttachmentKey,
    item_id: Uuid,
    bytes: Zeroizing<Vec<u8>>,
}

impl PendingAttachmentUpload {
    pub fn encrypt(mut self) -> AttachmentRequest {
        self.request.blob = B64.encode(attachment::encrypt_blob(
            &self.key,
            self.item_id.as_bytes(),
            self.request.attachment_id.as_bytes(),
            &self.bytes,
        ));
        self.request
    }
}

/// Prepare encrypted metadata while borrowing the vault key only for this call.
///
/// This checks the per-field and per-file limits only. A host that knows the
/// item's current encrypted attachment total must also call [`validate_upload`]
/// with that total; the service enforces the per-item aggregate atomically.
pub fn prepare_upload(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment_id: Uuid,
    upload: AttachmentUpload,
    sha256: Option<&[u8; 32]>,
) -> Result<PendingAttachmentUpload, ResolverError> {
    validate_upload(
        upload.bytes.len(),
        upload.filename.len(),
        upload.content_type.len(),
        0,
    )?;
    let key = attachment::generate_attachment_key();
    let item = item_id.as_bytes();
    let id = attachment_id.as_bytes();
    let request = AttachmentRequest {
        attachment_id,
        blob: String::new(),
        filename_ciphertext: B64.encode(attachment::encrypt_filename(
            vault_key,
            item,
            id,
            &upload.filename,
        )),
        content_type_ciphertext: B64.encode(attachment::encrypt_content_type(
            vault_key,
            item,
            id,
            &upload.content_type,
        )),
        wrapped_content_key: B64.encode(attachment::wrap_attachment_key(vault_key, item, id, &key)),
        digest_ciphertext: sha256
            .map(|digest| B64.encode(attachment::encrypt_digest(&key, item, id, digest))),
    };
    Ok(PendingAttachmentUpload {
        request,
        key,
        item_id,
        bytes: upload.bytes,
    })
}

fn build_attachment_request(
    vault_key: &VaultKey,
    item_id: Uuid,
    attachment_id: Uuid,
    upload: AttachmentUpload,
    sha256: Option<&[u8; 32]>,
) -> Result<serde_json::Value, ResolverError> {
    serde_json::to_value(
        prepare_upload(vault_key, item_id, attachment_id, upload, sha256)?.encrypt(),
    )
    .map_err(|_| ResolverError::Malformed("attachment request"))
}

/// Open a bounded attachment blob after its metadata and key have been verified.
pub fn decrypt_blob(
    key: &seren_secrets_crypto::keys::AttachmentKey,
    item_id: Uuid,
    attachment_id: Uuid,
    encoded: &str,
    encrypted_size: u64,
) -> Result<Zeroizing<Vec<u8>>, ResolverError> {
    let limit = usize::try_from(encrypted_size)
        .map_err(|_| ResolverError::Malformed("attachment blob size"))?;
    if !(ENVELOPE_BYTES + 1..=MAX_ENCRYPTED_BYTES).contains(&limit) {
        return Err(ResolverError::Malformed("attachment blob size"));
    }
    let blob = bounded_decode(encoded, limit)?;
    if blob.len() != limit {
        return Err(ResolverError::Malformed("attachment blob size"));
    }
    let bytes = Zeroizing::new(attachment::decrypt_blob(
        key,
        item_id.as_bytes(),
        attachment_id.as_bytes(),
        &blob,
    )?);
    if bytes.len() + ENVELOPE_BYTES != limit {
        return Err(ResolverError::Malformed("attachment plaintext size"));
    }
    Ok(bytes)
}

impl VaultClient {
    /// List attachment metadata using the existing read/approval route, without
    /// blobs. Each summary carries its opened SHA-256 when one was stored.
    pub async fn list_attachments(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<Vec<AttachmentSummary>, ResolverError> {
        let listed = self
            .list_attachment_records(vault_id, item_id, vault_key)
            .await?;
        Ok(listed.into_iter().map(|(_, summary)| summary).collect())
    }

    /// The listed records, each beside its verified summary.
    async fn list_attachment_records(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<Vec<(AttachmentRecord, AttachmentSummary)>, ResolverError> {
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
            .into_iter()
            .map(|record| {
                if !seen.insert(record.attachment_id) {
                    return Err(ResolverError::ResponseMismatch);
                }
                let summary = attachment_summary(vault_key, item_id, &record)?;
                total = total
                    .checked_add(summary.encrypted_size_bytes)
                    .ok_or(ResolverError::Malformed("attachment total size"))?;
                if total > MAX_ITEM_ENCRYPTED_BYTES {
                    return Err(ResolverError::Malformed("attachment total size"));
                }
                Ok((record, summary))
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
        let key = attachment::unwrap_attachment_key(
            vault_key,
            item_id.as_bytes(),
            attachment_id.as_bytes(),
            &bounded_decode(&response.record.wrapped_content_key, MAX_METADATA_BYTES)?,
        )?;
        let bytes = decrypt_blob(
            &key,
            item_id,
            attachment_id,
            &response.blob,
            summary.encrypted_size_bytes,
        )?;
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
        let body = build_attachment_request(vault_key, item_id, attachment_id, upload, None)?;
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

    /// Encrypt and upload under the caller-chosen `attachment_id`, only while
    /// the parent item is still at `if_match_item_updated_at`. The body also
    /// carries the file's SHA-256 sealed under the attachment key, so later
    /// reads can verify the file without downloading it.
    ///
    /// When the item already has the id, the client reads the attachment list
    /// and reports `AlreadyPresent` only if that attachment's SHA-256, name and
    /// size all match this upload; otherwise, or when another item uses the
    /// id, `IdConflict`. Key rotation returns [`ResolverError::Rotating`].
    pub async fn put_attachment_with_id(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        attachment_id: Uuid,
        vault_key: &VaultKey,
        upload: AttachmentUpload,
        if_match_item_updated_at: Timestamp,
    ) -> Result<AttachmentWrite<AttachmentPutOutcome>, ResolverError> {
        // Keep only the digest, size and name for the duplicate check; the
        // plaintext bytes still drop before I/O.
        let sha256 = attachment::plaintext_digest(&upload.bytes);
        let size_bytes = upload.bytes.len() as u64;
        let filename = upload.filename.clone();
        let body =
            build_attachment_request(vault_key, item_id, attachment_id, upload, Some(&sha256))?;
        let result = self
            .call_with_options(
                reqwest::Method::POST,
                &format!("/vaults/{vault_id}/items/{item_id}/attachments"),
                Some(body),
                Some(if_match_item_updated_at),
                MAX_GATEWAY_BODY,
            )
            .await;
        let value = match result {
            Ok(value) => value,
            Err(ResolverError::ServerError { status: 412, .. }) => {
                return Ok(AttachmentWrite {
                    outcome: AttachmentPutOutcome::Stale,
                    item_updated_at: None,
                });
            }
            Err(error) if is_coded_server_error(&error, 409, "attachment_already_exists") => {
                let listed = self.list_attachments(vault_id, item_id, vault_key).await?;
                let same_file = listed.iter().any(|listed| {
                    listed.attachment_id == attachment_id
                        && listed.sha256 == Some(sha256)
                        && *listed.filename == *filename
                        && listed.size_bytes == size_bytes
                });
                return Ok(AttachmentWrite {
                    outcome: if same_file {
                        AttachmentPutOutcome::AlreadyPresent
                    } else {
                        AttachmentPutOutcome::IdConflict
                    },
                    item_updated_at: Some(if_match_item_updated_at),
                });
            }
            Err(error) if is_coded_server_error(&error, 409, "attachment_id_conflict") => {
                return Ok(AttachmentWrite {
                    outcome: AttachmentPutOutcome::IdConflict,
                    item_updated_at: Some(if_match_item_updated_at),
                });
            }
            Err(error) => return Err(item_write_error(error)),
        };
        let created: CreatedAttachment = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("created attachment"))?;
        if created.record.attachment_id != attachment_id {
            return Err(ResolverError::ResponseMismatch);
        }
        let summary = attachment_summary(vault_key, item_id, &created.record)?;
        if summary.encrypted_size_bytes != size_bytes + ENVELOPE_BYTES as u64 {
            return Err(ResolverError::Malformed("created attachment size"));
        }
        if summary.sha256 != Some(sha256) {
            return Err(ResolverError::ResponseMismatch);
        }
        Ok(AttachmentWrite {
            item_updated_at: Some(parse_item_updated_at(&created.item_updated_at)?),
            outcome: AttachmentPutOutcome::Created(summary),
        })
    }

    /// Delete one attachment only while the parent item is still at
    /// `if_match_item_updated_at` and the attachment still holds the file
    /// whose SHA-256 is `expected_sha256`. This never deletes the item and
    /// never uses the unconditional `DELETE` route.
    ///
    /// The client reads the attachment list to find this attachment's stored
    /// digest ciphertext and sends those exact bytes only if they open to
    /// `expected_sha256`. Otherwise (no such attachment, or a digest that is
    /// different, missing or unreadable) it sends a fresh digest seal under an
    /// independent throwaway key as a non-matching guard. The service decides the
    /// outcome in the transaction that checks the revision: it deletes only a
    /// row holding exactly the sent bytes, refuses a stale revision first, and
    /// otherwise reports the attachment absent or mismatched. Every outcome
    /// therefore reflects the guarded write, never a local guess. Key rotation
    /// returns [`ResolverError::Rotating`].
    pub async fn conditional_delete_attachment(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
        attachment_id: Uuid,
        vault_key: &VaultKey,
        expected_sha256: &[u8; 32],
        if_match_item_updated_at: Timestamp,
    ) -> Result<AttachmentWrite<AttachmentDeleteOutcome>, ResolverError> {
        let listed = self
            .list_attachment_records(vault_id, item_id, vault_key)
            .await?;
        let stored = listed
            .iter()
            .find(|(record, summary)| {
                record.attachment_id == attachment_id
                    && summary.sha256.as_ref() == Some(expected_sha256)
            })
            .and_then(|(record, _)| record.digest_ciphertext.clone());
        // An independent fresh seal is a non-matching guard. The service still
        // checks the revision before reporting absence or a mismatch.
        let expected_digest_ciphertext = stored.unwrap_or_else(|| {
            B64.encode(attachment::encrypt_digest(
                &attachment::generate_attachment_key(),
                item_id.as_bytes(),
                attachment_id.as_bytes(),
                expected_sha256,
            ))
        });
        let result = self
            .call_with_options(
                reqwest::Method::POST,
                &format!("/vaults/{vault_id}/items/{item_id}/attachments/{attachment_id}/deletion"),
                Some(serde_json::json!({
                    "expected_digest_ciphertext": expected_digest_ciphertext,
                })),
                Some(if_match_item_updated_at),
                MAX_GATEWAY_BODY,
            )
            .await;
        let value = match result {
            Ok(value) => value,
            Err(ResolverError::ServerError { status: 412, .. }) => {
                return Ok(AttachmentWrite {
                    outcome: AttachmentDeleteOutcome::Stale,
                    item_updated_at: None,
                });
            }
            Err(error) if is_coded_server_error(&error, 409, "attachment_digest_mismatch") => {
                return Ok(AttachmentWrite {
                    outcome: AttachmentDeleteOutcome::Mismatch,
                    item_updated_at: Some(if_match_item_updated_at),
                });
            }
            Err(error) => return Err(item_write_error(error)),
        };
        let response: ConditionalDeleteResponse = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("attachment deletion outcome"))?;
        Ok(AttachmentWrite {
            outcome: match response.state {
                ConditionalDeleteState::Deleted => AttachmentDeleteOutcome::Deleted,
                ConditionalDeleteState::AlreadyAbsent => AttachmentDeleteOutcome::AlreadyAbsent,
            },
            item_updated_at: Some(parse_item_updated_at(&response.item_updated_at)?),
        })
    }
}

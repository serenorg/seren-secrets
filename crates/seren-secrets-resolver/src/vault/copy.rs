//! Copy approvals: a requester reads the items an owner approved for one copy.
//!
//! The owner's browser seals a fresh one-time transfer key for the requester
//! and re-wraps each approved item's title, tags, metadata, content key and
//! attachment fields under it, with the same ids in every AAD as the vault
//! key uses. The requester never sees the vault key. Only the existing
//! vault, item and attachment functions open this material.

use super::*;
use seren_secrets_crypto::keys::AttachmentKey;
use seren_secrets_crypto::protocol::attachment;

use super::attachments::{
    MAX_DOWNLOAD_RESPONSE_BYTES, MAX_METADATA_BYTES, bounded_decode, decrypt_blob, encrypted_size,
};

/// Most items a copy approval may name, and most `replaced_item_ids`.
pub const MAX_COPY_ITEMS: usize = 1000;

/// A copy approval as its requester sees it.
pub enum CopyApproval {
    Pending,
    Denied,
    Expired,
    /// The requester finished the copy; the approved material is gone.
    Completed,
    /// The owner approved these items. Every field is plaintext.
    Approved {
        vault_id: Uuid,
        vault_name: String,
        whole_vault: bool,
        expires_at: Timestamp,
        items: Vec<CopiedItem>,
    },
}

impl std::fmt::Debug for CopyApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => f.write_str("Pending"),
            Self::Denied => f.write_str("Denied"),
            Self::Expired => f.write_str("Expired"),
            Self::Completed => f.write_str("Completed"),
            Self::Approved {
                vault_id,
                whole_vault,
                expires_at,
                items,
                ..
            } => f
                .debug_struct("Approved")
                .field("vault_id", vault_id)
                .field("vault_name", &"<redacted>")
                .field("whole_vault", whole_vault)
                .field("expires_at", expires_at)
                .field("items", &items.len())
                .finish(),
        }
    }
}

/// One approved item, decrypted. Treat every field as sensitive; there is
/// deliberately no `Debug` implementation.
pub struct CopiedItem {
    pub item_id: Uuid,
    pub title: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub content: ItemContent,
    /// Exact server revision of the item.
    pub updated_at: ItemRevision,
    pub attachments: Vec<CopiedAttachment>,
}

/// One approved attachment's metadata. Download it with
/// [`VaultClient::copy_attachment`].
pub struct CopiedAttachment {
    pub attachment_id: Uuid,
    pub filename: Zeroizing<String>,
    /// An authenticated empty value represents absent metadata.
    pub content_type: Option<Zeroizing<String>>,
    /// Plaintext byte count.
    pub size_bytes: u64,
    /// SHA-256 of the plaintext, opened from the stored digest. `None` when
    /// none was stored.
    pub sha256: Option<[u8; 32]>,
}

#[derive(Deserialize)]
struct CopyApprovalRecord {
    request_id: Uuid,
    status: ApprovalStatus,
}

#[derive(Deserialize)]
struct CopyItemsView {
    vault_id: Uuid,
    whole_vault: bool,
    vault_name_ciphertext: String,
    expires_at: Timestamp,
    one_shot_wrapped_key: String,
    items: Vec<CopyItemView>,
}

#[derive(Deserialize)]
struct CopyItemView {
    item_id: Uuid,
    title_ciphertext: String,
    #[serde(default)]
    tags_ciphertext: Option<String>,
    metadata_ciphertext: String,
    content_key_wrap: String,
    content_ciphertext: String,
    updated_at: ItemRevision,
    #[serde(default)]
    attachments: Vec<CopyAttachmentView>,
}

#[derive(Deserialize)]
struct CopyAttachmentView {
    attachment_id: Uuid,
    size_bytes: i64,
    #[serde(default)]
    digest_ciphertext: Option<String>,
    filename_ciphertext: String,
    content_type_ciphertext: String,
    wrapped_content_key: String,
}

#[derive(Deserialize)]
struct CopyAttachmentBlob {
    blob: String,
}

#[derive(Deserialize)]
struct CreatedApproval {
    request_id: Uuid,
}

/// An approved attachment's verified key and sizes.
struct OpenedAttachment {
    summary: CopiedAttachment,
    key: AttachmentKey,
    encrypted_size: u64,
}

fn open_transfer_key(
    kem_private: &IdentityKemPrivateKey,
    view: &CopyItemsView,
) -> Result<VaultKey, ResolverError> {
    let wrapped = b64_decode(&view.one_shot_wrapped_key, "one_shot_wrapped_key")?;
    Ok(unwrap_vault_key(kem_private, &wrapped)?)
}

fn open_attachment(
    transfer_key: &VaultKey,
    item_id: Uuid,
    view: &CopyAttachmentView,
) -> Result<OpenedAttachment, ResolverError> {
    let encrypted_size = encrypted_size(view.size_bytes)?;
    let item = item_id.as_bytes();
    let id = view.attachment_id.as_bytes();
    let key = attachment::unwrap_attachment_key(
        transfer_key,
        item,
        id,
        &bounded_decode(&view.wrapped_content_key, MAX_METADATA_BYTES)?,
    )?;
    let sha256 = match view.digest_ciphertext.as_deref() {
        Some(encoded) => Some(attachment::decrypt_digest(
            &key,
            item,
            id,
            &bounded_decode(encoded, MAX_METADATA_BYTES)?,
        )?),
        None => None,
    };
    let filename = Zeroizing::new(attachment::decrypt_filename(
        transfer_key,
        item,
        id,
        &bounded_decode(&view.filename_ciphertext, MAX_METADATA_BYTES)?,
    )?);
    let content_type = Zeroizing::new(attachment::decrypt_content_type(
        transfer_key,
        item,
        id,
        &bounded_decode(&view.content_type_ciphertext, MAX_METADATA_BYTES)?,
    )?);
    Ok(OpenedAttachment {
        summary: CopiedAttachment {
            attachment_id: view.attachment_id,
            filename,
            content_type: (!content_type.is_empty()).then_some(content_type),
            size_bytes: encrypted_size - attachments::ENVELOPE_BYTES as u64,
            sha256,
        },
        key,
        encrypted_size,
    })
}

fn open_item(transfer_key: &VaultKey, view: CopyItemView) -> Result<CopiedItem, ResolverError> {
    let item_id = view.item_id;
    let aad = item_id.as_bytes();
    let content_key = unwrap_item_content_key(
        transfer_key,
        aad,
        &b64_decode(&view.content_key_wrap, "content_key_wrap")?,
    )?;
    let content = decrypt_item_with_content_key(
        &content_key,
        aad,
        &b64_decode(&view.content_ciphertext, "content_ciphertext")?,
    )?;
    let title = decrypt_title(
        transfer_key,
        aad,
        &b64_decode(&view.title_ciphertext, "title_ciphertext")?,
    )?;
    let tags = match &view.tags_ciphertext {
        Some(tags) => decrypt_tags(transfer_key, aad, &b64_decode(tags, "tags_ciphertext")?)?,
        None => Vec::new(),
    };
    let metadata_json = Zeroizing::new(decrypt_metadata_json(
        transfer_key,
        aad,
        &b64_decode(&view.metadata_ciphertext, "metadata_ciphertext")?,
    )?);
    let (favorite, _) = metadata_flags(&metadata_json);
    let mut seen = std::collections::HashSet::new();
    let attachments = view
        .attachments
        .iter()
        .map(|attachment| {
            if !seen.insert(attachment.attachment_id) {
                return Err(ResolverError::ResponseMismatch);
            }
            open_attachment(transfer_key, item_id, attachment).map(|opened| opened.summary)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CopiedItem {
        item_id,
        title,
        tags,
        favorite,
        content: content.into_inner(),
        updated_at: view.updated_at,
        attachments,
    })
}

impl VaultClient {
    /// Ask the requesting agent's owner to approve a copy of items they
    /// choose from one vault. `replaced_item_ids` are items this requester
    /// copied before, at most 1,000 and without duplicates. Returns the
    /// approval id.
    pub async fn request_copy_approval(
        &self,
        replaced_item_ids: &[Uuid],
    ) -> Result<Uuid, ResolverError> {
        let unique: std::collections::HashSet<_> = replaced_item_ids.iter().collect();
        if replaced_item_ids.len() > MAX_COPY_ITEMS || unique.len() != replaced_item_ids.len() {
            return Err(ResolverError::InvalidInput("replaced_item_ids"));
        }
        let value = self
            .call(
                reqwest::Method::POST,
                "/approvals",
                Some(serde_json::json!({
                    "target_kind": "copy",
                    "timeout_seconds": 86_400,
                    "replaced_item_ids": replaced_item_ids,
                })),
            )
            .await?;
        let created: CreatedApproval = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("approval record"))?;
        Ok(created.request_id)
    }

    /// Read a copy approval. Once approved, read its items and decrypt them
    /// with the one-time key the owner sealed for this caller. Every item
    /// opens or the call fails: no partial result is returned.
    pub async fn copy_approval(&self, approval_id: Uuid) -> Result<CopyApproval, ResolverError> {
        let value = self
            .call(
                reqwest::Method::GET,
                &format!("/approvals/{approval_id}"),
                None,
            )
            .await?;
        let record: CopyApprovalRecord = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("approval record"))?;
        if record.request_id != approval_id {
            return Err(ResolverError::ResponseMismatch);
        }
        match record.status {
            ApprovalStatus::Pending => return Ok(CopyApproval::Pending),
            ApprovalStatus::Denied => return Ok(CopyApproval::Denied),
            ApprovalStatus::Expired => return Ok(CopyApproval::Expired),
            ApprovalStatus::Completed => return Ok(CopyApproval::Completed),
            ApprovalStatus::Approved => {}
        }
        let view = self.copy_items_view(approval_id).await?;
        let kem = self.key_source.kem_private()?;
        let transfer_key = open_transfer_key(&kem, &view)?;
        let vault_name = decrypt_vault_name(
            &transfer_key,
            view.vault_id.as_bytes(),
            &b64_decode(&view.vault_name_ciphertext, "vault_name_ciphertext")?,
        )?;
        let mut seen = std::collections::HashSet::new();
        let items = view
            .items
            .into_iter()
            .map(|item| {
                if !seen.insert(item.item_id) {
                    return Err(ResolverError::ResponseMismatch);
                }
                open_item(&transfer_key, item)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CopyApproval::Approved {
            vault_id: view.vault_id,
            vault_name,
            whole_vault: view.whole_vault,
            expires_at: view.expires_at,
            items,
        })
    }

    /// Download one approved attachment, decrypt it with the one-time key and
    /// check it against its stored SHA-256 when one was stored.
    pub async fn copy_attachment(
        &self,
        approval_id: Uuid,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<Zeroizing<Vec<u8>>, ResolverError> {
        let view = self.copy_items_view(approval_id).await?;
        let kem = self.key_source.kem_private()?;
        let transfer_key = open_transfer_key(&kem, &view)?;
        let record = view
            .items
            .iter()
            .find(|item| item.item_id == item_id)
            .and_then(|item| {
                item.attachments
                    .iter()
                    .find(|attachment| attachment.attachment_id == attachment_id)
            })
            // The service answers 404 for anything outside the approval; a
            // local miss reads the same so callers handle one outcome.
            .ok_or_else(|| ResolverError::ServerError {
                status: 404,
                body: "not in copy approval".into(),
            })?;
        let opened = open_attachment(&transfer_key, item_id, record)?;
        drop(transfer_key);
        let value = self
            .call_with_options(
                reqwest::Method::GET,
                &format!("/approvals/{approval_id}/items/{item_id}/attachments/{attachment_id}"),
                None,
                None,
                MAX_DOWNLOAD_RESPONSE_BYTES,
            )
            .await?;
        let response: CopyAttachmentBlob = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("attachment blob"))?;
        let bytes = decrypt_blob(
            &opened.key,
            item_id,
            attachment_id,
            &response.blob,
            opened.encrypted_size,
        )?;
        if let Some(expected) = opened.summary.sha256
            && attachment::plaintext_digest(&bytes) != expected
        {
            return Err(ResolverError::Malformed("attachment digest"));
        }
        Ok(bytes)
    }

    /// Tell the service the copy is finished, so it deletes the approved
    /// material. Repeating it is harmless.
    pub async fn complete_copy_approval(&self, approval_id: Uuid) -> Result<(), ResolverError> {
        self.call(
            reqwest::Method::POST,
            &format!("/approvals/{approval_id}/complete"),
            Some(serde_json::json!({})),
        )
        .await?;
        Ok(())
    }

    async fn copy_items_view(&self, approval_id: Uuid) -> Result<CopyItemsView, ResolverError> {
        let value = self
            .call(
                reqwest::Method::GET,
                &format!("/approvals/{approval_id}/items"),
                None,
            )
            .await?;
        let view: CopyItemsView = serde_json::from_value(value)
            .map_err(|_| ResolverError::Malformed("copy approval items"))?;
        if view.items.len() > MAX_COPY_ITEMS {
            return Err(ResolverError::Malformed("copy approval items"));
        }
        Ok(view)
    }
}

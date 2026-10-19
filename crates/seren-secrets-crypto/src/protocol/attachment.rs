//! Attachment encryption.
//!
//! Each attachment has its own random XChaCha20-Poly1305 key (the
//! `AttachmentKey`). The key is wrapped under the owning vault's
//! `VaultKey` and stored alongside the encrypted blob in the
//! `item_attachments` row. The blob itself lives in the per-org database,
//! encrypted under the attachment key with AAD that binds the ciphertext to
//! both the item id and the attachment id.
//!
//! Filename, content-type, and the wrapped attachment key are stored
//! encrypted alongside the row, each sealed with the vault key under its own
//! AAD prefix bound to `(item_id, attachment_id)`. The wrap AAD binding
//! mirrors `wrap_item_content_key` and means a server that re-routes a
//! `wrapped_content_key` between rows fails AEAD verification without
//! relying on a downstream blob decrypt to catch the mismatch.
//!
//! The optional digest is the SHA-256 of the plaintext file, sealed under the
//! attachment key like the blob but under its own AAD prefix. Item moves and
//! vault key rotation re-wrap only the attachment key, so the digest stays
//! readable without being rewritten.

use sha2::{Digest, Sha256};

use crate::aead::{xchacha20_decrypt_with_aad, xchacha20_encrypt_with_aad};
use crate::error::CryptoResult;
use crate::keys::{AttachmentKey, VaultKey};

/// Generate a fresh attachment key.
pub fn generate_attachment_key() -> AttachmentKey {
    AttachmentKey::random()
}

fn wrap_aad(item_id: &[u8], attachment_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + attachment_id.len() + 24);
    aad.extend_from_slice(b"attachment-content-key:");
    aad.extend_from_slice(item_id);
    aad.push(b':');
    aad.extend_from_slice(attachment_id);
    aad
}

/// Wrap an attachment key under the vault key. The result is an AEAD blob
/// stored in `item_attachments.wrapped_content_key`. The AAD binds the wrap
/// to the owning (item, attachment) pair.
pub fn wrap_attachment_key(
    vault_key: &VaultKey,
    item_id: &[u8],
    attachment_id: &[u8],
    attachment_key: &AttachmentKey,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        attachment_key.as_bytes(),
        &wrap_aad(item_id, attachment_id),
    )
}

/// Unwrap an attachment key wrapped with [`wrap_attachment_key`]. The caller
/// must supply the same (item, attachment) ids the wrap was produced with;
/// the AEAD tag verifies against the AAD layout so a cross-row swap fails.
pub fn unwrap_attachment_key(
    vault_key: &VaultKey,
    item_id: &[u8],
    attachment_id: &[u8],
    wrapped: &[u8],
) -> CryptoResult<AttachmentKey> {
    // Zeroizing: this buffer is the raw attachment key; wipe it once copied
    // into the self-zeroizing newtype.
    let bytes = zeroize::Zeroizing::new(xchacha20_decrypt_with_aad(
        vault_key.as_bytes(),
        wrapped,
        &wrap_aad(item_id, attachment_id),
    )?);
    if bytes.len() != 32 {
        return Err(crate::error::CryptoError::InvalidKey(
            "attachment key must be 32 bytes",
        ));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(AttachmentKey::from_bytes(buf))
}

/// AAD used when sealing the attachment blob. Binds the ciphertext to both
/// the parent item id and the attachment id, so swapping blobs between
/// attachments fails AEAD verification.
fn blob_aad(item_id: &[u8], attachment_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + attachment_id.len() + 16);
    aad.extend_from_slice(b"attachment-blob:");
    aad.extend_from_slice(item_id);
    aad.push(b':');
    aad.extend_from_slice(attachment_id);
    aad
}

fn filename_aad(item_id: &[u8], attachment_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + attachment_id.len() + 20);
    aad.extend_from_slice(b"attachment-filename:");
    aad.extend_from_slice(item_id);
    aad.push(b':');
    aad.extend_from_slice(attachment_id);
    aad
}

fn content_type_aad(item_id: &[u8], attachment_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + attachment_id.len() + 24);
    aad.extend_from_slice(b"attachment-content-type:");
    aad.extend_from_slice(item_id);
    aad.push(b':');
    aad.extend_from_slice(attachment_id);
    aad
}

/// AAD for the sealed plaintext digest. Its prefix differs from the blob's,
/// so a digest ciphertext can never open as a blob or as another
/// attachment's digest.
fn digest_aad(item_id: &[u8], attachment_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(item_id.len() + attachment_id.len() + 19);
    aad.extend_from_slice(b"attachment-digest:");
    aad.extend_from_slice(item_id);
    aad.push(b':');
    aad.extend_from_slice(attachment_id);
    aad
}

/// SHA-256 of an attachment's plaintext bytes, the value [`encrypt_digest`] seals.
pub fn plaintext_digest(plaintext: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(plaintext));
    out
}

/// Seal a plaintext digest under the attachment's own key, bound to the
/// owning (item, attachment) pair.
pub fn encrypt_digest(
    attachment_key: &AttachmentKey,
    item_id: &[u8],
    attachment_id: &[u8],
    digest: &[u8; 32],
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        attachment_key.as_bytes(),
        digest,
        &digest_aad(item_id, attachment_id),
    )
}

/// Open a digest sealed with [`encrypt_digest`]. Anything but exactly 32
/// plaintext bytes is rejected.
pub fn decrypt_digest(
    attachment_key: &AttachmentKey,
    item_id: &[u8],
    attachment_id: &[u8],
    ciphertext: &[u8],
) -> CryptoResult<[u8; 32]> {
    let pt = xchacha20_decrypt_with_aad(
        attachment_key.as_bytes(),
        ciphertext,
        &digest_aad(item_id, attachment_id),
    )?;
    pt.try_into()
        .map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_blob(
    attachment_key: &AttachmentKey,
    item_id: &[u8],
    attachment_id: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        attachment_key.as_bytes(),
        plaintext,
        &blob_aad(item_id, attachment_id),
    )
}

pub fn decrypt_blob(
    attachment_key: &AttachmentKey,
    item_id: &[u8],
    attachment_id: &[u8],
    blob: &[u8],
) -> CryptoResult<Vec<u8>> {
    xchacha20_decrypt_with_aad(
        attachment_key.as_bytes(),
        blob,
        &blob_aad(item_id, attachment_id),
    )
}

pub fn encrypt_filename(
    vault_key: &VaultKey,
    item_id: &[u8],
    attachment_id: &[u8],
    filename: &str,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        filename.as_bytes(),
        &filename_aad(item_id, attachment_id),
    )
}

pub fn decrypt_filename(
    vault_key: &VaultKey,
    item_id: &[u8],
    attachment_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(
        vault_key.as_bytes(),
        blob,
        &filename_aad(item_id, attachment_id),
    )?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

pub fn encrypt_content_type(
    vault_key: &VaultKey,
    item_id: &[u8],
    attachment_id: &[u8],
    content_type: &str,
) -> Vec<u8> {
    xchacha20_encrypt_with_aad(
        vault_key.as_bytes(),
        content_type.as_bytes(),
        &content_type_aad(item_id, attachment_id),
    )
}

pub fn decrypt_content_type(
    vault_key: &VaultKey,
    item_id: &[u8],
    attachment_id: &[u8],
    blob: &[u8],
) -> CryptoResult<String> {
    let pt = xchacha20_decrypt_with_aad(
        vault_key.as_bytes(),
        blob,
        &content_type_aad(item_id, attachment_id),
    )?;
    String::from_utf8(pt).map_err(|_| crate::error::CryptoError::InvalidCiphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn expect2_sep(prefix: &[u8], item_id: &[u8], attachment_id: &[u8]) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.extend_from_slice(item_id);
        v.push(b':');
        v.extend_from_slice(attachment_id);
        v
    }

    /// Frozen AAD layout for attachment slots. Unlike the vault email slots,
    /// these insert a ':' between the two ids; the exact bytes are pinned as
    /// the cross-implementation canary.
    #[test]
    fn attachment_aad_layout_is_frozen() {
        let item_id = [0x33u8; 16];
        let att_id = [0x44u8; 16];
        assert_eq!(
            wrap_aad(&item_id, &att_id),
            expect2_sep(b"attachment-content-key:", &item_id, &att_id)
        );
        assert_eq!(
            blob_aad(&item_id, &att_id),
            expect2_sep(b"attachment-blob:", &item_id, &att_id)
        );
        assert_eq!(
            filename_aad(&item_id, &att_id),
            expect2_sep(b"attachment-filename:", &item_id, &att_id)
        );
        assert_eq!(
            content_type_aad(&item_id, &att_id),
            expect2_sep(b"attachment-content-type:", &item_id, &att_id)
        );
        assert_eq!(
            digest_aad(&item_id, &att_id),
            expect2_sep(b"attachment-digest:", &item_id, &att_id)
        );
    }

    #[test]
    fn digest_round_trips_and_never_opens_as_a_blob_or_another_digest() {
        let key = generate_attachment_key();
        let item = Uuid::new_v4();
        let att = Uuid::new_v4();
        // SHA-256("abc"), FIPS 180-2 appendix B.1.
        let digest = plaintext_digest(b"abc");
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        let ct = encrypt_digest(&key, item.as_bytes(), att.as_bytes(), &digest);
        assert_eq!(
            decrypt_digest(&key, item.as_bytes(), att.as_bytes(), &ct).unwrap(),
            digest
        );
        let other = Uuid::new_v4();
        for (i, a) in [(other, att), (item, other)] {
            assert!(matches!(
                decrypt_digest(&key, i.as_bytes(), a.as_bytes(), &ct),
                Err(crate::error::CryptoError::AuthFailure)
            ));
        }
        // The domain prefix separates digest and blob under the same key.
        assert!(decrypt_blob(&key, item.as_bytes(), att.as_bytes(), &ct).is_err());
        let blob = encrypt_blob(&key, item.as_bytes(), att.as_bytes(), &digest);
        assert!(decrypt_digest(&key, item.as_bytes(), att.as_bytes(), &blob).is_err());
        // A sealed value of the wrong length is not a digest.
        let short = xchacha20_encrypt_with_aad(
            key.as_bytes(),
            &digest[..31],
            &digest_aad(item.as_bytes(), att.as_bytes()),
        );
        assert!(matches!(
            decrypt_digest(&key, item.as_bytes(), att.as_bytes(), &short),
            Err(crate::error::CryptoError::InvalidCiphertext)
        ));
    }

    #[test]
    fn round_trip_blob() {
        let vault = VaultKey::random();
        let attachment = generate_attachment_key();
        let item_id = Uuid::new_v4();
        let att_id = Uuid::new_v4();
        let wrapped =
            wrap_attachment_key(&vault, item_id.as_bytes(), att_id.as_bytes(), &attachment);
        let unwrapped =
            unwrap_attachment_key(&vault, item_id.as_bytes(), att_id.as_bytes(), &wrapped).unwrap();
        assert_eq!(attachment.as_bytes(), unwrapped.as_bytes());

        let plaintext = b"binary attachment bytes";
        let ct = encrypt_blob(
            &attachment,
            item_id.as_bytes(),
            att_id.as_bytes(),
            plaintext,
        );
        let recovered =
            decrypt_blob(&attachment, item_id.as_bytes(), att_id.as_bytes(), &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn blob_aad_binds_to_both_ids() {
        let attachment = generate_attachment_key();
        let item_a = Uuid::new_v4();
        let item_b = Uuid::new_v4();
        let att_a = Uuid::new_v4();
        let att_b = Uuid::new_v4();
        let ct = encrypt_blob(&attachment, item_a.as_bytes(), att_a.as_bytes(), b"hi");
        // Same attachment id, different item id - rejected.
        let err = decrypt_blob(&attachment, item_b.as_bytes(), att_a.as_bytes(), &ct).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
        // Same item, different attachment id - rejected.
        let err = decrypt_blob(&attachment, item_a.as_bytes(), att_b.as_bytes(), &ct).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn filename_round_trip_and_aad_binding() {
        let vault = VaultKey::random();
        let item = Uuid::new_v4();
        let att = Uuid::new_v4();
        let ct = encrypt_filename(&vault, item.as_bytes(), att.as_bytes(), "secret.pdf");
        let pt = decrypt_filename(&vault, item.as_bytes(), att.as_bytes(), &ct).unwrap();
        assert_eq!(pt, "secret.pdf");
        // Different attachment id fails.
        let other = Uuid::new_v4();
        let err = decrypt_filename(&vault, item.as_bytes(), other.as_bytes(), &ct).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn content_type_round_trip() {
        let vault = VaultKey::random();
        let item = Uuid::new_v4();
        let att = Uuid::new_v4();
        let ct = encrypt_content_type(&vault, item.as_bytes(), att.as_bytes(), "application/pdf");
        let pt = decrypt_content_type(&vault, item.as_bytes(), att.as_bytes(), &ct).unwrap();
        assert_eq!(pt, "application/pdf");
    }

    #[test]
    fn wrong_vault_cannot_unwrap_attachment_key() {
        let vault_a = VaultKey::random();
        let vault_b = VaultKey::random();
        let attachment = generate_attachment_key();
        let item = Uuid::new_v4();
        let att = Uuid::new_v4();
        let wrapped = wrap_attachment_key(&vault_a, item.as_bytes(), att.as_bytes(), &attachment);
        let err =
            unwrap_attachment_key(&vault_b, item.as_bytes(), att.as_bytes(), &wrapped).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }

    #[test]
    fn wrap_aad_binds_to_both_ids() {
        // The AAD binds the wrap to (item_id, attachment_id).
        let vault = VaultKey::random();
        let attachment = generate_attachment_key();
        let item_a = Uuid::new_v4();
        let item_b = Uuid::new_v4();
        let att_a = Uuid::new_v4();
        let att_b = Uuid::new_v4();
        let wrapped = wrap_attachment_key(&vault, item_a.as_bytes(), att_a.as_bytes(), &attachment);
        let err = unwrap_attachment_key(&vault, item_b.as_bytes(), att_a.as_bytes(), &wrapped)
            .unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
        let err = unwrap_attachment_key(&vault, item_a.as_bytes(), att_b.as_bytes(), &wrapped)
            .unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::AuthFailure));
    }
}

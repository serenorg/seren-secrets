//! Offline decryption and field projection for an already authorized browser
//! grant. Hosts retain the browser identity key outside models, scripts and
//! the general resolver, and deliver values only to their protected browser.

use std::{collections::BTreeMap, fmt};

use seren_secrets_crypto::{
    CryptoError,
    keys::IdentityKemPrivateKey,
    protocol::item::{
        ItemContent, decrypt_item_with_content_key, unwrap_item_content_key_for_identity,
    },
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::seren_secrets::project_field;

/// A field cannot be projected. Names and values are intentionally omitted.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldProjectionError {
    #[error("unknown or empty field")]
    UnknownField,
    #[error("invalid field value")]
    InvalidValue,
}

/// Browser grant refusals contain only static reasons, never input or secrets.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrowserGrantError {
    #[error("wrong browser key or invalid wrapped item key")]
    KeyUnwrap,
    #[error("item mismatch or invalid content ciphertext")]
    ItemMismatch,
    #[error("invalid decrypted item content")]
    InvalidContent,
    #[error("unsupported item kind; browser grants require login or card")]
    UnsupportedKind,
    #[error("declared and decrypted item kind mismatch")]
    KindMismatch,
    #[error(transparent)]
    Field(#[from] FieldProjectionError),
}

/// Only the requested fields, scrubbed on drop and redacted in `Debug`.
/// Values must only be used by the host's protected browser filling path.
pub struct BrowserGrantFields {
    fields: BTreeMap<String, Zeroizing<String>>,
}

impl BrowserGrantFields {
    /// Deliberately access a value by its exact requested field name. Aliases
    /// not present in the request are absent even if they name the same value.
    pub fn get(&self, field: &str) -> Option<&str> {
        self.fields.get(field).map(|value| value.as_str())
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl fmt::Debug for BrowserGrantFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BrowserGrantFields")
            .field(&"<redacted>")
            .finish()
    }
}

/// Read requested fields from an already authorized Login or Card grant.
///
/// Byte inputs are decoded wire ciphertexts, not base64 strings. The declared
/// kind must be the exact wire name (`login` or `card`). Body authentication
/// binds the expected `item_id`, and the authenticated kind must match the
/// declaration. Unknown, empty or invalid fields fail the entire request;
/// previously projected values and the decrypted body are scrubbed on failure.
///
/// This is not grant authorization: the caller must check the authenticated
/// service response, hire, hostname, revocation and expiry before each fill.
/// Sealed boxes do not authenticate their sender. Never expose these values
/// or the browser private key to model/tool output, scripts, logs or traces.
pub fn read_browser_grant(
    item_id: Uuid,
    declared_kind: &str,
    content_ciphertext: &[u8],
    recipient_wrapped_item_key: &[u8],
    browser_private_key: &IdentityKemPrivateKey,
    requested_fields: &[&str],
) -> Result<BrowserGrantFields, BrowserGrantError> {
    if !matches!(declared_kind, "login" | "card") {
        return Err(BrowserGrantError::UnsupportedKind);
    }
    let key = unwrap_item_content_key_for_identity(browser_private_key, recipient_wrapped_item_key)
        .map_err(|_| BrowserGrantError::KeyUnwrap)?;
    let content = decrypt_item_with_content_key(&key, item_id.as_bytes(), content_ciphertext)
        .map_err(|error| match error {
            CryptoError::Import(_) => BrowserGrantError::InvalidContent,
            _ => BrowserGrantError::ItemMismatch,
        })?;
    let actual_kind = match content.as_ref() {
        ItemContent::Login(_) => "login",
        ItemContent::Card(_) => "card",
        _ => return Err(BrowserGrantError::UnsupportedKind),
    };
    if declared_kind != actual_kind {
        return Err(BrowserGrantError::KindMismatch);
    }
    let mut fields = BTreeMap::new();
    for &field in requested_fields {
        fields.insert(field.to_owned(), project_field(content.as_ref(), field)?);
    }
    Ok(BrowserGrantFields { fields })
}

//! Versioned wire-format helpers used by every wrapping and AEAD blob.
//!
//! Every byte slice that crosses the network or is stored in the database
//! starts with a single version byte, followed by a small format-tag byte that
//! identifies the kind of payload (account wrap, sealed box, AEAD blob, etc.).
//! This lets future versions of the protocol be added without ambiguity.

use crate::error::{CryptoError, CryptoResult};

pub const PROTOCOL_VERSION: u8 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// XChaCha20-Poly1305 sealed envelope: 24-byte nonce || ciphertext || tag.
    AeadXChaCha = 0x01,
    /// `crypto_box` sealed box: 32-byte ephemeral pubkey || ciphertext || tag.
    SealedBox = 0x02,
    /// HMAC-SHA256 (used for blind indexes).
    HmacSha256 = 0x03,
    /// Ed25519 signature (64 bytes).
    Ed25519Sig = 0x04,
    /// Reserved master-key wrap tag. Pinned in the tag space, not yet used.
    AccountWrap = 0x05,
}

impl Tag {
    pub fn from_u8(byte: u8) -> CryptoResult<Self> {
        match byte {
            0x01 => Ok(Self::AeadXChaCha),
            0x02 => Ok(Self::SealedBox),
            0x03 => Ok(Self::HmacSha256),
            0x04 => Ok(Self::Ed25519Sig),
            0x05 => Ok(Self::AccountWrap),
            _ => Err(CryptoError::MalformedWire("unknown tag")),
        }
    }
}

/// Prepend the protocol version + tag to `payload` and return a fresh vector.
pub fn encode(tag: Tag, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 2);
    out.push(PROTOCOL_VERSION);
    out.push(tag as u8);
    out.extend_from_slice(payload);
    out
}

/// Split a versioned blob into `(tag, payload)`, validating the version byte.
pub fn decode(blob: &[u8]) -> CryptoResult<(Tag, &[u8])> {
    if blob.len() < 2 {
        return Err(CryptoError::MalformedWire("blob too short"));
    }
    if blob[0] != PROTOCOL_VERSION {
        return Err(CryptoError::UnsupportedVersion(blob[0]));
    }
    let tag = Tag::from_u8(blob[1])?;
    Ok((tag, &blob[2..]))
}

/// Like [`decode`], but errors if the tag is not `expected`.
pub fn decode_expecting(blob: &[u8], expected: Tag) -> CryptoResult<&[u8]> {
    let (tag, payload) = decode(blob)?;
    if tag != expected {
        return Err(CryptoError::MalformedWire("unexpected tag"));
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{Tag, decode, decode_expecting, encode};

    #[test]
    fn round_trip() {
        let payload = b"hello".as_slice();
        let encoded = encode(Tag::AeadXChaCha, payload);
        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[1], 0x01);
        assert_eq!(&encoded[2..], payload);
        let (tag, decoded) = decode(&encoded).unwrap();
        assert_eq!(tag, Tag::AeadXChaCha);
        assert_eq!(decoded, payload);
    }

    #[test]
    fn rejects_wrong_tag() {
        let blob = encode(Tag::SealedBox, b"x");
        let err = decode_expecting(&blob, Tag::AeadXChaCha).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::MalformedWire(_)));
    }

    #[test]
    fn rejects_short_blob() {
        let err = decode(&[1]).unwrap_err();
        assert!(matches!(err, crate::error::CryptoError::MalformedWire(_)));
    }

    #[test]
    fn rejects_unknown_version() {
        let err = decode(&[99, 1]).unwrap_err();
        assert!(matches!(
            err,
            crate::error::CryptoError::UnsupportedVersion(99)
        ));
    }
}

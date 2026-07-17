//! Strongly-typed key newtypes. All sensitive types zeroize on drop.
//!
//! Public-key types are `Clone + Copy` because they're inert. Private-key
//! and symmetric-key types are not `Copy` and are wrapped so callers cannot
//! accidentally retain unzeroized copies.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::entropy::fill_random;
use crate::error::{CryptoError, CryptoResult};

const X25519_KEY_LEN: usize = 32;
const ED25519_PUBLIC_LEN: usize = 32;
const ED25519_SECRET_LEN: usize = 32;
const SYMMETRIC_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Symmetric keys (32-byte AEAD keys)
// ---------------------------------------------------------------------------

macro_rules! symmetric_key {
    ($name:ident, $purpose:literal) => {
        #[doc = concat!("32-byte symmetric key used for ", $purpose, ".")]
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name(pub(crate) [u8; SYMMETRIC_KEY_LEN]);

        impl $name {
            pub fn from_bytes(bytes: [u8; SYMMETRIC_KEY_LEN]) -> Self {
                Self(bytes)
            }

            pub fn random() -> Self {
                let mut bytes = [0u8; SYMMETRIC_KEY_LEN];
                fill_random(&mut bytes);
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; SYMMETRIC_KEY_LEN] {
                &self.0
            }

            pub fn to_vec(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&"<redacted>")
                    .finish()
            }
        }
    };
}

symmetric_key!(MasterKey, "deriving wraps around the account key");
symmetric_key!(
    AccountKey,
    "deriving identity keypairs and wrapping account secrets"
);
symmetric_key!(VaultKey, "AEAD encryption of items inside a vault");
symmetric_key!(RecoveryDerivedKey, "wrapping the account key for recovery");
symmetric_key!(BlindIndexKey, "HMAC-SHA256 blind-index lookups (per-vault)");
symmetric_key!(AttachmentKey, "AEAD encryption of attachment blobs");
symmetric_key!(
    ItemContentKey,
    "AEAD encryption of an item body; wrapped under the vault key so an approval or share can hand off a single item without disclosing the whole vault"
);

// ---------------------------------------------------------------------------
// X25519 KEM keypair
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityKemPublicKey(pub [u8; X25519_KEY_LEN]);

impl IdentityKemPublicKey {
    pub fn from_bytes(bytes: [u8; X25519_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != X25519_KEY_LEN {
            return Err(CryptoError::InvalidKey(
                "X25519 public key must be 32 bytes",
            ));
        }
        let mut buf = [0u8; X25519_KEY_LEN];
        buf.copy_from_slice(slice);
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; X25519_KEY_LEN] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKemPrivateKey(pub(crate) [u8; X25519_KEY_LEN]);

impl IdentityKemPrivateKey {
    pub fn from_bytes(bytes: [u8; X25519_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != X25519_KEY_LEN {
            return Err(CryptoError::InvalidKey(
                "X25519 private key must be 32 bytes",
            ));
        }
        let mut buf = [0u8; X25519_KEY_LEN];
        buf.copy_from_slice(slice);
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; X25519_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for IdentityKemPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IdentityKemPrivateKey")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct IdentityKemKeypair {
    pub public: IdentityKemPublicKey,
    pub private: IdentityKemPrivateKey,
}

impl IdentityKemKeypair {
    pub fn generate() -> Self {
        let mut private = [0u8; X25519_KEY_LEN];
        fill_random(&mut private);
        let secret = x25519_dalek::StaticSecret::from(private);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self {
            public: IdentityKemPublicKey(*public.as_bytes()),
            private: IdentityKemPrivateKey(secret.to_bytes()),
        }
    }

    pub fn from_private(private: IdentityKemPrivateKey) -> Self {
        let secret = x25519_dalek::StaticSecret::from(private.0);
        let public = x25519_dalek::PublicKey::from(&secret);
        let public_bytes = *public.as_bytes();
        Self {
            public: IdentityKemPublicKey(public_bytes),
            private,
        }
    }
}

// ---------------------------------------------------------------------------
// Ed25519 signing keypair
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentitySigningPublicKey(pub [u8; ED25519_PUBLIC_LEN]);

impl IdentitySigningPublicKey {
    pub fn from_bytes(bytes: [u8; ED25519_PUBLIC_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != ED25519_PUBLIC_LEN {
            return Err(CryptoError::InvalidKey(
                "Ed25519 public key must be 32 bytes",
            ));
        }
        let mut buf = [0u8; ED25519_PUBLIC_LEN];
        buf.copy_from_slice(slice);
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_LEN] {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySigningPrivateKey(pub(crate) [u8; ED25519_SECRET_LEN]);

impl IdentitySigningPrivateKey {
    pub fn from_bytes(bytes: [u8; ED25519_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> CryptoResult<Self> {
        if slice.len() != ED25519_SECRET_LEN {
            return Err(CryptoError::InvalidKey(
                "Ed25519 private key must be 32 bytes",
            ));
        }
        let mut buf = [0u8; ED25519_SECRET_LEN];
        buf.copy_from_slice(slice);
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; ED25519_SECRET_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for IdentitySigningPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IdentitySigningPrivateKey")
            .field(&"<redacted>")
            .finish()
    }
}

pub struct IdentitySigningKeypair {
    pub public: IdentitySigningPublicKey,
    pub private: IdentitySigningPrivateKey,
}

impl IdentitySigningKeypair {
    pub fn generate() -> Self {
        let mut private = [0u8; ED25519_SECRET_LEN];
        fill_random(&mut private);
        let signing = ed25519_dalek::SigningKey::from_bytes(&private);
        let verifying = signing.verifying_key();
        Self {
            public: IdentitySigningPublicKey(verifying.to_bytes()),
            private: IdentitySigningPrivateKey(signing.to_bytes()),
        }
    }

    pub fn from_private(private: IdentitySigningPrivateKey) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(&private.0);
        let verifying = signing.verifying_key();
        Self {
            public: IdentitySigningPublicKey(verifying.to_bytes()),
            private,
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery key (user-facing base32 encoding)
// ---------------------------------------------------------------------------

const RECOVERY_KEY_BYTES: usize = 32;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey(pub(crate) [u8; RECOVERY_KEY_BYTES]);

impl RecoveryKey {
    pub fn random() -> Self {
        let mut buf = [0u8; RECOVERY_KEY_BYTES];
        fill_random(&mut buf);
        Self(buf)
    }

    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_BYTES] {
        &self.0
    }

    /// Encode as groups of 4 base32 characters separated by hyphens,
    /// e.g. `ABCD-EFGH-IJKL-...`.
    pub fn to_display_string(&self) -> String {
        let encoded = data_encoding::BASE32_NOPAD.encode(&self.0);
        // BASE32_NOPAD output is ASCII; build the hyphenated grouping by char
        // so there is no intermediate UTF-8 re-validation to unwrap.
        let mut out = String::with_capacity(encoded.len() + encoded.len() / 4);
        for (i, ch) in encoded.chars().enumerate() {
            if i > 0 && i.is_multiple_of(4) {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Parse a string in the format emitted by [`Self::to_display_string`].
    /// Tolerant of arbitrary whitespace and surrounding hyphens.
    pub fn from_display_string(s: &str) -> CryptoResult<Self> {
        // Zeroizing: both intermediates are encodings of the recovery key;
        // wipe them once the bytes land in the self-zeroizing newtype.
        let cleaned: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            s.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let decoded = zeroize::Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(cleaned.as_bytes())
                .map_err(|_| CryptoError::InvalidRecoveryKey)?,
        );
        if decoded.len() != RECOVERY_KEY_BYTES {
            return Err(CryptoError::InvalidRecoveryKey);
        }
        let mut buf = [0u8; RECOVERY_KEY_BYTES];
        buf.copy_from_slice(&decoded);
        Ok(Self(buf))
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RecoveryKey").field(&"<redacted>").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_keys_are_random() {
        let a = VaultKey::random();
        let b = VaultKey::random();
        assert_ne!(a.0, b.0);
    }

    #[test]
    fn x25519_keypair_public_matches_private() {
        let kp = IdentityKemKeypair::generate();
        let rebuilt = IdentityKemKeypair::from_private(kp.private.clone());
        assert_eq!(kp.public, rebuilt.public);
    }

    #[test]
    fn ed25519_keypair_public_matches_private() {
        let kp = IdentitySigningKeypair::generate();
        let rebuilt = IdentitySigningKeypair::from_private(kp.private.clone());
        assert_eq!(kp.public, rebuilt.public);
    }

    #[test]
    fn recovery_key_display_round_trip() {
        let rk = RecoveryKey::random();
        let display = rk.to_display_string();
        let parsed = RecoveryKey::from_display_string(&display).unwrap();
        assert_eq!(rk.0, parsed.0);
        assert!(display.contains('-'));
    }

    #[test]
    fn recovery_key_tolerates_whitespace_and_case() {
        let rk = RecoveryKey::random();
        let display = rk.to_display_string();
        let messy = format!("\t {} \n  ", display.to_lowercase());
        let parsed = RecoveryKey::from_display_string(&messy).unwrap();
        assert_eq!(rk.0, parsed.0);
    }

    #[test]
    fn recovery_key_rejects_wrong_length() {
        let bad = "AAAA-BBBB";
        let err = RecoveryKey::from_display_string(bad).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidRecoveryKey));
    }

    #[test]
    fn key_debug_redacts() {
        let k = VaultKey::random();
        assert!(format!("{k:?}").contains("redacted"));
        let kem = IdentityKemKeypair::generate();
        assert!(format!("{:?}", kem.private).contains("redacted"));
    }
}

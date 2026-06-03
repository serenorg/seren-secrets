//! Per-vault HMAC-SHA256 blind index for exact title lookup.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::keys::BlindIndexKey;
use crate::wire::{Tag, encode};

type HmacSha256 = Hmac<Sha256>;

/// Normalize a title (case-fold, NFKC, strip whitespace edges) and return the
/// HMAC-SHA256 under the given per-vault blind-index key. Output is a versioned
/// blob so future hash algorithms can be added.
pub fn blind_index_title(key: &BlindIndexKey, title: &str) -> Vec<u8> {
    let normalized = normalize_title(title);
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any 32-byte key");
    mac.update(normalized.as_bytes());
    let bytes = mac.finalize().into_bytes();
    encode(Tag::HmacSha256, &bytes)
}

fn normalize_title(title: &str) -> String {
    title.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Tag, decode_expecting};

    #[test]
    fn deterministic_for_same_title_and_key() {
        let k = BlindIndexKey::from_bytes([0xAB; 32]);
        let a = blind_index_title(&k, "Example Login");
        let b = blind_index_title(&k, "  example LOGIN  ");
        assert_eq!(a, b);
    }

    #[test]
    fn different_titles_diverge() {
        let k = BlindIndexKey::from_bytes([0xCD; 32]);
        let a = blind_index_title(&k, "alpha");
        let b = blind_index_title(&k, "beta");
        assert_ne!(a, b);
    }

    #[test]
    fn different_keys_diverge() {
        let k1 = BlindIndexKey::from_bytes([1; 32]);
        let k2 = BlindIndexKey::from_bytes([2; 32]);
        let a = blind_index_title(&k1, "same");
        let b = blind_index_title(&k2, "same");
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_32_bytes() {
        let k = BlindIndexKey::from_bytes([0; 32]);
        let blob = blind_index_title(&k, "x");
        let payload = decode_expecting(&blob, Tag::HmacSha256).unwrap();
        assert_eq!(payload.len(), 32);
    }
}

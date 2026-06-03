//! Client-side password generation from typed recipes.
//!
//! The server never sees a generated password. Recipes are intentionally
//! limited; complex policies belong in the client UI.

use rand::RngExt;
use rand::rng;
use rand::seq::{IndexedRandom, SliceRandom};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, CryptoResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PasswordRecipe {
    /// Mixed character classes, length in [8, 256].
    Random {
        length: u32,
        #[serde(default = "default_true")]
        upper: bool,
        #[serde(default = "default_true")]
        lower: bool,
        #[serde(default = "default_true")]
        digits: bool,
        #[serde(default = "default_true")]
        symbols: bool,
    },
    /// Diceware-style passphrase. Word count in [4, 16].
    Passphrase {
        word_count: u32,
        separator: char,
        capitalize_first: bool,
    },
    /// Random hex of `length` characters (must be even).
    Hex { length: u32 },
}

fn default_true() -> bool {
    true
}

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

/// Generate a password from the given recipe. Returns the generated string.
///
/// The caller is responsible for handling the result securely (e.g., copying
/// to clipboard with a TTL, encrypting into a vault item). This function does
/// not retain plaintext.
pub fn generate(recipe: &PasswordRecipe) -> CryptoResult<String> {
    match recipe {
        PasswordRecipe::Random {
            length,
            upper,
            lower,
            digits,
            symbols,
        } => generate_random(*length as usize, *upper, *lower, *digits, *symbols),
        PasswordRecipe::Passphrase {
            word_count,
            separator,
            capitalize_first,
        } => generate_passphrase(*word_count as usize, *separator, *capitalize_first),
        PasswordRecipe::Hex { length } => generate_hex(*length as usize),
    }
}

fn generate_random(
    length: usize,
    upper: bool,
    lower: bool,
    digits: bool,
    symbols: bool,
) -> CryptoResult<String> {
    if !(8..=256).contains(&length) {
        return Err(CryptoError::InvalidPasswordRecipe(
            "random length must be 8..=256",
        ));
    }
    let mut alphabet: Vec<u8> = Vec::new();
    let mut required: Vec<&[u8]> = Vec::new();
    if upper {
        alphabet.extend_from_slice(UPPER);
        required.push(UPPER);
    }
    if lower {
        alphabet.extend_from_slice(LOWER);
        required.push(LOWER);
    }
    if digits {
        alphabet.extend_from_slice(DIGITS);
        required.push(DIGITS);
    }
    if symbols {
        alphabet.extend_from_slice(SYMBOLS);
        required.push(SYMBOLS);
    }
    if alphabet.is_empty() {
        return Err(CryptoError::InvalidPasswordRecipe(
            "at least one character class must be enabled",
        ));
    }
    if required.len() > length {
        return Err(CryptoError::InvalidPasswordRecipe(
            "length too short to include one of every required class",
        ));
    }
    let mut chars: Vec<u8> = Vec::with_capacity(length);
    let mut rng = rng();

    // Force at least one char from each enabled class.
    for class in &required {
        chars.push(pick(class, &mut rng));
    }
    while chars.len() < length {
        chars.push(pick(&alphabet, &mut rng));
    }
    // Shuffle so required-class characters are not always at the start.
    chars.shuffle(&mut rng);

    Ok(String::from_utf8(chars).expect("ASCII alphabet"))
}

fn pick<R: rand::Rng + ?Sized>(alphabet: &[u8], rng: &mut R) -> u8 {
    *alphabet.choose(rng).expect("validated non-empty alphabet")
}

/// EFF "large" diceware wordlist: 7776 words, ~12.9 bits per word.
///
/// Source: Electronic Frontier Foundation, `eff_large_wordlist.txt`
/// (https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt), CC BY 3.0 US.
/// The embedded file is that list verbatim.
fn wordlist() -> &'static [&'static str] {
    use std::sync::OnceLock;
    // The four hyphenated EFF entries are excluded so a separator-joined
    // passphrase is unambiguous; the entropy effect (7772 vs 7776) is
    // negligible.
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("../data/eff_large_wordlist.txt")
            .lines()
            .filter(|w| w.bytes().all(|b| b.is_ascii_lowercase()))
            .collect()
    })
}

fn generate_passphrase(
    word_count: usize,
    separator: char,
    capitalize_first: bool,
) -> CryptoResult<String> {
    if !(4..=16).contains(&word_count) {
        return Err(CryptoError::InvalidPasswordRecipe(
            "passphrase word count must be 4..=16",
        ));
    }
    let mut rng = rng();
    let mut out = String::new();
    for i in 0..word_count {
        if i > 0 {
            out.push(separator);
        }
        let list = wordlist();
        let word = *list.choose(&mut rng).expect("wordlist is not empty");
        if capitalize_first {
            let mut chars = word.chars();
            if let Some(c) = chars.next() {
                out.push(c.to_ascii_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
    }
    Ok(out)
}

fn generate_hex(length: usize) -> CryptoResult<String> {
    if length == 0 || length > 512 || !length.is_multiple_of(2) {
        return Err(CryptoError::InvalidPasswordRecipe(
            "hex length must be even and in 1..=512",
        ));
    }
    let byte_count = length / 2;
    let mut bytes = vec![0u8; byte_count];
    rng().fill(&mut bytes);
    let mut out = String::with_capacity(length);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_default() {
        let p = generate(&PasswordRecipe::Random {
            length: 20,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
        })
        .unwrap();
        assert_eq!(p.len(), 20);
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(p.chars().any(|c| SYMBOLS.contains(&(c as u8))));
    }

    #[test]
    fn random_only_lower() {
        let p = generate(&PasswordRecipe::Random {
            length: 16,
            upper: false,
            lower: true,
            digits: false,
            symbols: false,
        })
        .unwrap();
        assert_eq!(p.len(), 16);
        assert!(p.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn random_rejects_no_alphabet() {
        let err = generate(&PasswordRecipe::Random {
            length: 16,
            upper: false,
            lower: false,
            digits: false,
            symbols: false,
        })
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPasswordRecipe(_)));
    }

    #[test]
    fn random_rejects_short() {
        let err = generate(&PasswordRecipe::Random {
            length: 4,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
        })
        .unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPasswordRecipe(_)));
    }

    #[test]
    fn passphrase_default() {
        let p = generate(&PasswordRecipe::Passphrase {
            word_count: 5,
            separator: '-',
            capitalize_first: true,
        })
        .unwrap();
        assert_eq!(p.matches('-').count(), 4);
        assert!(p.chars().next().unwrap().is_ascii_uppercase());
    }

    #[test]
    fn hex_even() {
        let p = generate(&PasswordRecipe::Hex { length: 32 }).unwrap();
        assert_eq!(p.len(), 32);
        assert!(p.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hex_rejects_odd() {
        let err = generate(&PasswordRecipe::Hex { length: 31 }).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidPasswordRecipe(_)));
    }

    #[test]
    fn distinct_outputs() {
        let r = PasswordRecipe::Random {
            length: 16,
            upper: true,
            lower: true,
            digits: true,
            symbols: false,
        };
        let a = generate(&r).unwrap();
        let b = generate(&r).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wordlist_is_eff_large_list_minus_hyphenated() {
        let list = wordlist();
        // Canonical EFF large list is 7776 words; the 4 hyphenated entries are
        // dropped so separator-joined passphrases stay unambiguous.
        assert_eq!(list.len(), 7772);
        assert!(
            list.iter()
                .all(|w| w.bytes().all(|b| b.is_ascii_lowercase()))
        );
    }
}

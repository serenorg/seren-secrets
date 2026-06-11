//! Parser for the `otpauth://` URI scheme (RFC 6238 / Google Authenticator format).
//!
//! Input shapes:
//!   otpauth://totp/Issuer:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Issuer&algorithm=SHA1&digits=6&period=30
//!   otpauth://hotp/...  (not supported; treated as an error)
//!
//! Each successful parse yields a `Login` item carrying only the TOTP config;
//! username is set from the label and notes/password are left empty. Callers
//! that already have a parent Login item should merge the TOTP into it rather
//! than create a new one.

use super::ImportedItem;
use crate::error::{CryptoError, CryptoResult};
use crate::prose::ZeroizableJson;
use crate::protocol::item::{LoginContent, TotpAlgorithm, TotpConfig};

pub fn parse_otpauth_uri(uri: &str) -> CryptoResult<ImportedItem> {
    let body = uri.strip_prefix("otpauth://").ok_or(CryptoError::Import(
        "otpauth URI must start with otpauth://",
    ))?;

    let (kind, rest) = body
        .split_once('/')
        .ok_or(CryptoError::Import("otpauth URI missing type segment"))?;
    if !kind.eq_ignore_ascii_case("totp") {
        return Err(CryptoError::Import("only otpauth totp URIs are supported"));
    }

    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    // Per RFC 3986 the label is a URI path segment; `+` is literal there and
    // is only decoded to space inside query strings. Decode each half with the
    // right rule so a label like `My+Service` survives intact.
    let label = percent_decode_path(label);
    let (issuer_from_label, account_from_label) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None => (None, label),
    };

    let mut secret: Option<String> = None;
    let mut issuer: Option<String> = issuer_from_label;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: u8 = 6;
    let mut period_seconds: u32 = 30;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode_query(value);
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(value.replace([' ', '\t'], "").to_uppercase()),
            "issuer" if issuer.as_deref().is_none_or(str::is_empty) => {
                issuer = Some(value);
            }
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => TotpAlgorithm::Sha1,
                    "SHA256" => TotpAlgorithm::Sha256,
                    "SHA512" => TotpAlgorithm::Sha512,
                    _ => {
                        return Err(CryptoError::Import("unsupported otpauth algorithm"));
                    }
                };
            }
            "digits" => {
                digits = value
                    .parse::<u8>()
                    .map_err(|_| CryptoError::Import("invalid otpauth digits"))?;
                if !(4..=10).contains(&digits) {
                    return Err(CryptoError::Import("otpauth digits must be 4..=10"));
                }
            }
            "period" => {
                period_seconds = value
                    .parse::<u32>()
                    .map_err(|_| CryptoError::Import("invalid otpauth period"))?;
                if !(5..=300).contains(&period_seconds) {
                    return Err(CryptoError::Import("otpauth period must be 5..=300"));
                }
            }
            _ => {}
        }
    }

    let secret = secret.ok_or(CryptoError::Import("otpauth URI missing secret"))?;
    if !valid_base32(&secret) {
        return Err(CryptoError::Import(
            "otpauth secret must be base32 (RFC 4648)",
        ));
    }

    let title = match (&issuer, account_from_label.is_empty()) {
        (Some(i), false) => format!("{i}: {account_from_label}"),
        (Some(i), true) => i.clone(),
        (None, false) => account_from_label.clone(),
        (None, true) => "OTP".to_string(),
    };

    let login = LoginContent {
        username: account_from_label,
        password: String::new(),
        urls: Vec::new(),
        totp: Some(TotpConfig {
            secret_base32: secret,
            algorithm,
            digits,
            period_seconds,
        }),
        notes: crate::prose::ProseDoc::empty(),
        notes_text: String::new(),
        custom_fields: Vec::new(),
        password_history: Vec::new(),
        raw_import: ZeroizableJson::default(),
        ..Default::default()
    };

    Ok(ImportedItem::new_login(title, login))
}

/// Parse a multi-line block of otpauth URIs, skipping blank lines and comments.
/// Returns `(items, errors)` so callers can show partial successes.
pub fn parse_otpauth_uris(input: &str) -> (Vec<ImportedItem>, Vec<(usize, CryptoError)>) {
    let mut items = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_otpauth_uri(trimmed) {
            Ok(item) => items.push(item),
            Err(err) => errors.push((idx + 1, err)),
        }
    }
    (items, errors)
}

/// Percent-decoder for URI query-string values: `%XX` becomes a byte and `+`
/// becomes a space, per the application/x-www-form-urlencoded convention.
fn percent_decode_query(input: &str) -> String {
    decode_with(input, true)
}

/// Percent-decoder for URI path segments: `%XX` becomes a byte but `+` is
/// preserved literally (RFC 3986 reserves `+` only inside query strings).
fn percent_decode_path(input: &str) -> String {
    decode_with(input, false)
}

fn decode_with(input: &str, plus_to_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // i + 2 < bytes.len() means bytes[i + 2] is a valid index, so `%XX`
        // at the very end of the input is still handled.
        if b == b'%' && i + 2 < bytes.len() {
            let hi = hex_digit(bytes[i + 1]);
            let lo = hex_digit(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if plus_to_space && b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn valid_base32(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '='))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::item::ItemContent;

    #[test]
    fn parses_minimal_uri() {
        let uri = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let item = parse_otpauth_uri(uri).unwrap();
        assert_eq!(item.title, "Example: alice@example.com");
        match &item.content {
            ItemContent::Login(l) => {
                assert_eq!(l.username, "alice@example.com");
                let t = l.totp.as_ref().unwrap();
                assert_eq!(t.secret_base32, "JBSWY3DPEHPK3PXP");
                assert_eq!(t.algorithm, TotpAlgorithm::Sha1);
                assert_eq!(t.digits, 6);
                assert_eq!(t.period_seconds, 30);
            }
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn percent_decodes_label() {
        let uri = "otpauth://totp/Coinbase%20Pro:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60";
        let item = parse_otpauth_uri(uri).unwrap();
        assert_eq!(item.title, "Coinbase Pro: user@example.com");
        if let ItemContent::Login(l) = &item.content {
            let t = l.totp.as_ref().unwrap();
            assert_eq!(t.algorithm, TotpAlgorithm::Sha256);
            assert_eq!(t.digits, 8);
            assert_eq!(t.period_seconds, 60);
        } else {
            panic!("expected login");
        }
    }

    #[test]
    fn rejects_hotp() {
        let err = parse_otpauth_uri("otpauth://hotp/x?secret=A").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_non_base32_secret() {
        // 0 and 1 are deliberately not in the RFC 4648 base32 alphabet.
        let err = parse_otpauth_uri("otpauth://totp/x?secret=ABC0123&issuer=Y").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn rejects_missing_secret() {
        let err = parse_otpauth_uri("otpauth://totp/x?issuer=Y").unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn bulk_parse_skips_comments_and_blanks() {
        // The second URI's secret contains 0/1, which are not RFC 4648 base32.
        let input = "\n# header\n\notpauth://totp/A?secret=JBSWY3DPEHPK3PXP&issuer=A\notpauth://totp/B?secret=ABC0123\n";
        let (items, errors) = parse_otpauth_uris(input);
        assert_eq!(items.len(), 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].0, 5);
    }

    #[test]
    fn rejects_digits_out_of_range() {
        let err = parse_otpauth_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=Y&digits=12")
            .unwrap_err();
        assert!(matches!(err, CryptoError::Import(_)));
    }

    #[test]
    fn label_keeps_literal_plus_but_query_decodes_to_space() {
        // RFC 3986: `+` is literal in a URI path segment but decodes to space
        // in form-encoded query values. The label keeps `My+Service`; the
        // issuer query param decodes `Issuer+Name` to `Issuer Name`.
        let uri = "otpauth://totp/My+Service:alice?secret=JBSWY3DPEHPK3PXP&issuer=Issuer+Name";
        let item = parse_otpauth_uri(uri).unwrap();
        // Label issuer wins precedence, so the title carries the literal `+`.
        assert_eq!(item.title, "My+Service: alice");
        if let ItemContent::Login(l) = &item.content {
            assert_eq!(l.username, "alice");
        } else {
            panic!("expected login");
        }
    }
}

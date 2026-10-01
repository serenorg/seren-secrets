//! Ed25519 sign / verify.
//!
//! [`sign`] and [`verify`] operate on raw message bytes and back the
//! library-defined protocol payloads. Application-defined messages signed
//! with an identity key use [`sign_with_context`], which frames the message
//! under a library-owned domain and a caller-chosen context label so the
//! signature cannot verify as any library protocol payload or as a message
//! signed under a different context.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::error::{CryptoError, CryptoResult};
use crate::keys::{IdentitySigningPrivateKey, IdentitySigningPublicKey};
use crate::wire::{Tag, decode_expecting, encode};

const SIGNATURE_BYTES: usize = 64;

/// Domain-separation prefix for context signatures. No library protocol
/// payload begins with these bytes.
pub const CONTEXT_SIGNATURE_DOMAIN: &[u8] = b"seren-secrets/context-signature";

/// Maximum context label length; the label length is encoded in one byte.
pub const MAX_SIGNATURE_CONTEXT_LEN: usize = u8::MAX as usize;

pub fn sign(private: &IdentitySigningPrivateKey, message: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(private.as_bytes());
    let sig = signing.sign(message);
    encode(Tag::Ed25519Sig, &sig.to_bytes())
}

pub fn verify(public: &IdentitySigningPublicKey, message: &[u8], blob: &[u8]) -> CryptoResult<()> {
    let payload = decode_expecting(blob, Tag::Ed25519Sig)?;
    if payload.len() != SIGNATURE_BYTES {
        return Err(CryptoError::MalformedWire("ed25519 signature wrong length"));
    }
    let mut sig_bytes = [0u8; SIGNATURE_BYTES];
    sig_bytes.copy_from_slice(payload);
    let sig = Signature::from_bytes(&sig_bytes);
    let verifying = VerifyingKey::from_bytes(public.as_bytes())
        .map_err(|_| CryptoError::InvalidKey("ed25519 verifying key"))?;
    // verify_strict rejects small-order/non-canonical components for
    // malleability resistance, beyond the per-message id/challenge binding.
    verifying
        .verify_strict(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Canonical bytes covered by a context signature:
/// `CONTEXT_SIGNATURE_DOMAIN || u8(len(context)) || context || message`.
///
/// The context must be 1 to [`MAX_SIGNATURE_CONTEXT_LEN`] printable,
/// non-space ASCII bytes. The length prefix makes the context/message
/// boundary unambiguous.
pub fn context_signing_bytes(context: &str, message: &[u8]) -> CryptoResult<Vec<u8>> {
    let context = context.as_bytes();
    let context_len = u8::try_from(context.len())
        .ok()
        .filter(|len| *len > 0)
        .ok_or(CryptoError::Canonicalization(
            "signature context must be 1 to 255 bytes",
        ))?;
    if !context.iter().all(u8::is_ascii_graphic) {
        return Err(CryptoError::Canonicalization(
            "signature context must be printable non-space ASCII",
        ));
    }
    let mut out =
        Vec::with_capacity(CONTEXT_SIGNATURE_DOMAIN.len() + 1 + context.len() + message.len());
    out.extend_from_slice(CONTEXT_SIGNATURE_DOMAIN);
    out.push(context_len);
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    Ok(out)
}

/// Sign an application-defined `message` under `context`. Returns the
/// wire-enveloped Ed25519 signature checked by [`verify_with_context`].
pub fn sign_with_context(
    private: &IdentitySigningPrivateKey,
    context: &str,
    message: &[u8],
) -> CryptoResult<Vec<u8>> {
    Ok(sign(private, &context_signing_bytes(context, message)?))
}

/// Verify a signature produced by [`sign_with_context`] for the same
/// `context` and `message`.
pub fn verify_with_context(
    public: &IdentitySigningPublicKey,
    context: &str,
    message: &[u8],
    blob: &[u8],
) -> CryptoResult<()> {
    verify(public, &context_signing_bytes(context, message)?, blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentitySigningKeypair;

    #[test]
    fn round_trip() {
        let kp = IdentitySigningKeypair::generate();
        let msg = b"vault grant: alice -> agent-foo";
        let sig = sign(&kp.private, msg);
        verify(&kp.public, msg, &sig).unwrap();
    }

    #[test]
    fn wrong_signer_fails() {
        let kp1 = IdentitySigningKeypair::generate();
        let kp2 = IdentitySigningKeypair::generate();
        let sig = sign(&kp1.private, b"x");
        let err = verify(&kp2.public, b"x", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = IdentitySigningKeypair::generate();
        let sig = sign(&kp.private, b"original");
        let err = verify(&kp.public, b"tampered", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn context_signature_known_answer_vector_is_pinned() {
        // RFC 8032 section 7.1 TEST 1 key pair.
        const SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let private = hex::decode(SECRET).unwrap();
        let private = IdentitySigningPrivateKey::from_slice(&private).unwrap();
        let public = hex::decode(PUBLIC).unwrap();
        let public = IdentitySigningPublicKey::from_slice(&public).unwrap();
        let signed = context_signing_bytes("example.approval", b"hello").unwrap();
        let signature = sign_with_context(&private, "example.approval", b"hello").unwrap();

        assert_eq!(
            hex::encode(&signed),
            "736572656e2d736563726574732f636f6e746578742d7369676e6174757265106578616d706c652e617070726f76616c68656c6c6f",
        );
        assert_eq!(
            hex::encode(&signature),
            "0104ff40f113651cf0d2eaa3a8228d5af04a99a5c5bb9fd340971a22761b3b15d0f5fcb6429030a00347d520b44a36aa5788404f0586e0a15cff55db5cf20d254c04",
        );
        verify_with_context(&public, "example.approval", b"hello", &signature).unwrap();
    }

    #[test]
    fn context_signature_binds_context_message_and_key() {
        let kp = IdentitySigningKeypair::generate();
        let other = IdentitySigningKeypair::generate();
        let sig = sign_with_context(&kp.private, "example.approval", b"payload").unwrap();

        verify_with_context(&kp.public, "example.approval", b"payload", &sig).unwrap();
        for result in [
            verify_with_context(&kp.public, "example.approval", b"tampered", &sig),
            verify_with_context(&kp.public, "example.other", b"payload", &sig),
            verify_with_context(&other.public, "example.approval", b"payload", &sig),
            verify(&kp.public, b"payload", &sig),
        ] {
            assert!(matches!(result, Err(CryptoError::InvalidSignature)));
        }
    }

    #[test]
    fn context_boundary_is_unambiguous() {
        let kp = IdentitySigningKeypair::generate();
        assert_ne!(
            context_signing_bytes("ab", b"c").unwrap(),
            context_signing_bytes("a", b"bc").unwrap(),
        );
        let sig = sign_with_context(&kp.private, "ab", b"c").unwrap();
        let err = verify_with_context(&kp.public, "a", b"bc", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSignature));
    }

    #[test]
    fn context_label_is_validated() {
        let kp = IdentitySigningKeypair::generate();
        let longest = "a".repeat(MAX_SIGNATURE_CONTEXT_LEN);
        let sig = sign_with_context(&kp.private, &longest, b"m").unwrap();
        verify_with_context(&kp.public, &longest, b"m", &sig).unwrap();

        let too_long = "a".repeat(MAX_SIGNATURE_CONTEXT_LEN + 1);
        for context in ["", too_long.as_str(), "has space", "tab\t", "caf\u{e9}"] {
            assert!(matches!(
                sign_with_context(&kp.private, context, b"m"),
                Err(CryptoError::Canonicalization(_))
            ));
            assert!(matches!(
                verify_with_context(&kp.public, context, b"m", &sig),
                Err(CryptoError::Canonicalization(_))
            ));
        }
    }

    #[test]
    fn context_domain_is_disjoint_from_protocol_payload_prefixes() {
        let protocol_prefixes: [&[u8]; 6] = [
            crate::protocol::membership_grant::MEMBERSHIP_GRANT_DOMAIN,
            b"seren-secrets-resolve\n",
            b"seren-secrets-recovery-proof\n",
            b"seren-secrets-account-secrets-update\n",
            b"approval-request\n",
            // JSON-canonical payloads (agent creation, delegation contributions).
            b"{",
        ];
        for prefix in protocol_prefixes {
            assert!(!CONTEXT_SIGNATURE_DOMAIN.starts_with(prefix));
            assert!(!prefix.starts_with(CONTEXT_SIGNATURE_DOMAIN));
        }
    }
}

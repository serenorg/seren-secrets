//! Pure crypto primitives and protocol building blocks for `seren-secrets`.
//!
//! This crate is the only place private-key operations live. It performs no
//! I/O, no async work, and has no KMS dependencies. KMS adapters and any
//! upstream service that consumes these wire formats live outside this
//! crate; consumers depend on it only for public-key validation and the
//! shared wire-format helpers, and never hold the private keys it builds.
//!
//! ## Modules
//!
//! - [`kdf`] - Argon2id wrappers with parameter upgrade helpers.
//! - [`aead`] - XChaCha20-Poly1305 envelope encryption.
//! - [`kem`] - X25519 sealed-box wrap/unwrap.
//! - [`signing`] - Ed25519 sign / verify.
//! - [`keys`] - Strongly-typed key newtypes, all zeroizing on drop.
//! - [`password_generator`] - Client-side password generation from typed recipes.
//! - [`protocol`] - High-level account, vault, item, recovery, and approval flows.
//! - [`import`] - Parsers for 1Password `.1pux`, Bitwarden encrypted JSON,
//!   generic CSV, and `otpauth://` URIs.
//! - [`export`] - Encrypted JSON backup format.
//! - [`prose`] - ProseMirror content shape for typed item bodies.
//! - [`wire`] - Versioned wire-format helpers shared by every other module.

pub mod aead;
pub mod error;
pub mod export;
pub mod import;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod password_generator;
pub mod prose;
pub mod protocol;
pub mod signing;
pub mod wire;
pub mod zeroize_ext;

pub use error::{CryptoError, CryptoResult};
pub use prose::ZeroizableJson;
pub use zeroize_ext::ZeroizableBTreeMap;

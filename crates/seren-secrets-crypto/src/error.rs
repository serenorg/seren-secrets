use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key material: {0}")]
    InvalidKey(&'static str),

    #[error("invalid ciphertext")]
    InvalidCiphertext,

    #[error("authentication failed: tampered ciphertext or wrong key")]
    AuthFailure,

    #[error("unsupported wire-format version {0}")]
    UnsupportedVersion(u8),

    #[error("malformed wire format: {0}")]
    MalformedWire(&'static str),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("kdf failure: {0}")]
    Kdf(&'static str),

    #[error("invalid recovery key encoding")]
    InvalidRecoveryKey,

    #[error("password generator received invalid recipe: {0}")]
    InvalidPasswordRecipe(&'static str),

    #[error("import error: {0}")]
    Import(&'static str),

    #[error("export error: {0}")]
    Export(&'static str),

    #[error("canonicalization error: {0}")]
    Canonicalization(&'static str),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

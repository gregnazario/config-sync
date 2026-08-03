use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid envelope magic or version")]
    BadMagic,
    #[error("envelope too short / truncated")]
    Truncated,
    #[error("AEAD authentication failed")]
    AuthFailed,
    #[error("KEM operation failed")]
    Kem,
    #[error("invalid key length")]
    KeyLength,
    #[error("encoding error: {0}")]
    Encode(String),
}

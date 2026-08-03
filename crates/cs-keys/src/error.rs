use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeysError {
    #[error("secret not found")]
    NotFound,
    #[error("keychain error: {0}")]
    Keychain(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] cs_crypto::CryptoError),
    #[error("recovery error: {0}")]
    Recovery(String),
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("storage error: {0}")]
    Storage(#[from] cs_storage::StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] cs_crypto::CryptoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest error: {0}")]
    Manifest(String),
    #[error("conflict requires resolution but no resolver was provided")]
    UnresolvedConflict,
    #[error("conflict resolution aborted by user")]
    Aborted,
    #[error("cas retries exhausted after {0} attempts")]
    CasRetriesExhausted(u32),
}

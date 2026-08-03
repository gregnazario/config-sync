use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("etag mismatch (concurrent modification)")]
    PreconditionFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("backend: {0}")]
    Backend(String),
}

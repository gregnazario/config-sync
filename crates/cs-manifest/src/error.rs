use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("decode error: {0}")]
    Decode(String),
    #[error("schema version mismatch: got {0}")]
    SchemaVersion(u32),
}

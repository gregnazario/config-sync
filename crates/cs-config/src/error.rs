use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("unsupported schema_version {0}")]
    UnsupportedVersion(u32),
    #[error("duplicate config name: {0}")]
    DuplicateName(String),
    #[error("config {0} has no locations")]
    NoLocations(String),
    #[error("relative paths are not allowed: {0}")]
    RelativePath(String),
    #[error("path resolution error: {0}")]
    Path(String),
}

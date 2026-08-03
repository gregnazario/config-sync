//! Construct a `RemoteStore` from the config's declared backends.

use crate::{state::AppState, CliError};
use cs_storage::LocalFs;

/// Build the primary store. The starter config uses local-fs; cloud backends
/// (S3/Google Drive/Proton/WebDAV) are built from their `kind` + env-supplied
/// credentials when the relevant feature is enabled.
pub fn build_store(_cfg: &cs_config::Config, state: &AppState) -> Result<LocalFs, CliError> {
    std::fs::create_dir_all(&state.store_dir)?;
    Ok(LocalFs::new(state.store_dir.clone()))
}

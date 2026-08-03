//! config-sync CLI library. Subcommand implementations live here so they can be
//! unit-tested without spawning a process.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod state;
mod store;

pub use cli::{Cli, Command};
pub use commands::run;
pub use state::{AppState, AppStore};
pub use store::build_store;

use thiserror::Error;

/// Errors surfaced to the CLI's top level. `Plain` carries a pre-formatted
/// user-facing message (e.g. "no config found; run `config-sync init` first").
#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Plain(String),
    #[error("config error: {0}")]
    Config(#[from] cs_config::ConfigError),
    #[error("keys error: {0}")]
    Keys(#[from] cs_keys::KeysError),
    #[error("sync error: {0}")]
    Sync(#[from] cs_sync::SyncError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Storage(#[from] cs_storage::StorageError),
}

//! Construct a `RemoteStore` from the config's declared backends.
//!
//! The starter config uses a local directory under the config dir, but the
//! store path is configurable — so it can point at any folder a cloud-sync
//! client manages: **Proton Drive** (`~/Proton Drive/`), **iCloud Drive**
//! (`~/Library/Mobile Documents/`), Dropbox, OneDrive, Syncthing, etc. In that
//! mode the blobs are written to the synced folder and the cloud client
//! transparently uploads them — no reverse-engineered provider API needed.

use crate::{state::AppState, CliError};
use cs_storage::LocalFs;
use std::path::PathBuf;

/// Build the primary local store. If the config's primary backend declares a
/// `path`, use it (expanding `~`); otherwise default to `<config_dir>/store`.
pub fn build_store(cfg: &cs_config::Config, state: &AppState) -> Result<LocalFs, CliError> {
    let path = state.store_path_for(cfg);
    std::fs::create_dir_all(&path)?;
    Ok(LocalFs::new(path))
}

impl AppState {
    /// Resolve the store directory from the config, expanding a leading `~`.
    /// Falls back to `<config_dir>/store` when no path is configured.
    pub fn store_path_for(&self, cfg: &cs_config::Config) -> PathBuf {
        let primary = cfg
            .storage
            .backends
            .iter()
            .find(|b| b.name == cfg.storage.primary);
        if let Some(backend) = primary {
            if let Some(toml::Value::String(s)) = backend.opts.get("path") {
                if let Some(p) = expand_tilde(s) {
                    return p;
                }
                return PathBuf::from(s);
            }
        }
        self.store_dir.clone()
    }
}

/// Expand a leading `~/` (or a bare `~`) to the user's home directory.
fn expand_tilde(s: &str) -> Option<PathBuf> {
    if let Some(rest) = s.strip_prefix("~/") {
        dirs::home_dir().map(|h| h.join(rest))
    } else if s == "~" {
        dirs::home_dir()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_path_is_config_store_dir() {
        let root = TempDir::new().unwrap();
        let state = AppState::for_test(root.path());
        let cfg = cs_config::Config {
            schema_version: 1,
            identity: cs_config::Identity::default(),
            configs: vec![],
            storage: cs_config::StorageConfig {
                primary: "local".into(),
                secondary: vec![],
                backends: vec![],
            },
        };
        assert_eq!(state.store_path_for(&cfg), state.store_dir);
    }

    #[test]
    fn configured_path_overrides_default() {
        let root = TempDir::new().unwrap();
        let state = AppState::for_test(root.path());
        let mut opts = std::collections::BTreeMap::new();
        opts.insert(
            "path".to_string(),
            toml::Value::String("/tmp/explicit-store".into()),
        );
        let cfg = cs_config::Config {
            schema_version: 1,
            identity: cs_config::Identity::default(),
            configs: vec![],
            storage: cs_config::StorageConfig {
                primary: "local".into(),
                secondary: vec![],
                backends: vec![cs_config::Backend {
                    name: "local".into(),
                    kind: "local-fs".into(),
                    opts,
                }],
            },
        };
        assert_eq!(
            state.store_path_for(&cfg),
            PathBuf::from("/tmp/explicit-store")
        );
    }

    #[test]
    fn tilde_path_expands_to_home() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_tilde("~/x").unwrap(), home.join("x"));
        assert_eq!(expand_tilde("~").unwrap(), home);
        assert_eq!(expand_tilde("/abs"), None); // absolute paths are returned as-is elsewhere
    }
}

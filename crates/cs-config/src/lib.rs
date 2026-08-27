//! config-sync config schema: versioned TOML with per-machine path maps.

#![forbid(unsafe_code)]

mod error;
mod path;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub use error::ConfigError;
pub use path::{resolve, Platform};

/// The TOML schema version this build understands.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub identity: Identity,
    /// The managed config sets. Renamed from the TOML `[[config]]` table.
    #[serde(default, rename = "config")]
    pub configs: Vec<ConfigSet>,
    #[serde(default)]
    pub storage: StorageConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default)]
    pub device_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigSet {
    pub name: String,
    #[serde(default = "default_policy")]
    pub conflict_policy: ConflictPolicy,
    #[serde(default)]
    pub ignore: Vec<String>,
    /// The per-machine locations. Renamed from `[[config.location]]`.
    #[serde(default, rename = "location")]
    pub locations: Vec<Location>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

fn default_policy() -> ConflictPolicy {
    ConflictPolicy::Prompt
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictPolicy {
    LatestWins,
    Prompt,
    Manual,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Location {
    /// Hostname to match. Empty string means "any host".
    #[serde(default)]
    pub host: String,
    /// Platform to match (`mac`, `windows`, `linux`, `freebsd`). Empty = any.
    #[serde(default)]
    pub platform: String,
    pub path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub primary: String,
    #[serde(default)]
    pub secondary: Vec<String>,
    #[serde(default, rename = "backend")]
    pub backends: Vec<Backend>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Backend {
    pub name: String,
    pub kind: String,
    /// Remaining backend-specific options (bucket, region, prefix, path, …).
    #[serde(flatten)]
    pub opts: BTreeMap<String, toml::Value>,
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let c: Config = toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn from_path(p: &std::path::Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(p).map_err(|e| ConfigError::Parse(e.to_string()))?;
        Self::from_toml_str(&s)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(ConfigError::UnsupportedVersion(self.schema_version));
        }
        let mut seen = std::collections::HashSet::new();
        for cs in &self.configs {
            if !seen.insert(&cs.name) {
                return Err(ConfigError::DuplicateName(cs.name.clone()));
            }
            if cs.locations.is_empty() {
                return Err(ConfigError::NoLocations(cs.name.clone()));
            }
            for loc in &cs.locations {
                if !is_absolute_ish(&loc.path) {
                    return Err(ConfigError::RelativePath(loc.path.clone()));
                }
            }
        }
        Ok(())
    }
}

/// A path is "absolute-ish" (acceptable) if it starts with `~`, `/`, a Windows
/// drive letter (`C:\` or `C:/`), or a `%VAR%` reference. Anything else is
/// treated as relative and rejected at validation time.
pub fn is_absolute_ish(path: &str) -> bool {
    if path.starts_with('~') || path.starts_with('/') {
        return true;
    }
    if path.starts_with('%') {
        return true;
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../tests/fixtures/sample.toml");

    #[test]
    fn parses_spec_example() {
        let c = Config::from_toml_str(SAMPLE).unwrap();
        assert_eq!(c.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(c.configs.len(), 1);
        assert_eq!(c.configs[0].name, "vim");
        assert_eq!(c.configs[0].locations.len(), 3);
        assert_eq!(c.configs[0].conflict_policy, ConflictPolicy::Prompt);
    }

    #[test]
    fn empty_fields_preserved() {
        let c = Config::from_toml_str(SAMPLE).unwrap();
        assert_eq!(c.configs[0].fields.get("theme"), Some(&String::new()));
    }

    #[test]
    fn empty_host_and_platform_mean_any() {
        let c = Config::from_toml_str(SAMPLE).unwrap();
        let linux_loc = c.configs[0]
            .locations
            .iter()
            .find(|l| l.platform == "linux")
            .unwrap();
        assert_eq!(linux_loc.host, ""); // empty = any host
    }

    #[test]
    fn rejects_duplicate_names() {
        let bad = r#"
schema_version = 1
[[config]]
name = "x"
[[config.location]]
path = "~/.x"
[[config]]
name = "x"
[[config.location]]
path = "~/.x2"
"#;
        assert!(matches!(
            Config::from_toml_str(bad).err().unwrap(),
            ConfigError::DuplicateName(_)
        ));
    }

    #[test]
    fn rejects_relative_path() {
        let bad = r#"
schema_version = 1
[[config]]
name = "x"
[[config.location]]
path = "relative/path"
"#;
        assert!(matches!(
            Config::from_toml_str(bad).err().unwrap(),
            ConfigError::RelativePath(_)
        ));
    }

    #[test]
    fn rejects_no_locations() {
        let bad = r#"
schema_version = 1
[[config]]
name = "x"
"#;
        assert!(matches!(
            Config::from_toml_str(bad).err().unwrap(),
            ConfigError::NoLocations(_)
        ));
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let bad = r#"
schema_version = 99
[[config]]
name = "x"
[[config.location]]
path = "~/.x"
"#;
        assert!(matches!(
            Config::from_toml_str(bad).err().unwrap(),
            ConfigError::UnsupportedVersion(99)
        ));
    }

    #[test]
    fn unknown_keys_are_tolerated() {
        let s = r#"
schema_version = 1
future_field = "ignored"
[[config]]
name = "x"
extra = "ok"
[[config.location]]
path = "~/.x"
"#;
        assert!(Config::from_toml_str(s).is_ok());
    }

    #[test]
    fn windows_drive_letter_path_is_accepted() {
        let s = r#"
schema_version = 1
[[config]]
name = "x"
[[config.location]]
path = "C:/Users/g/x"
"#;
        assert!(Config::from_toml_str(s).is_ok());
    }

    #[test]
    fn storage_primary_and_secondary_parsed() {
        let c = Config::from_toml_str(SAMPLE).unwrap();
        assert_eq!(c.storage.primary, "local-repo");
        assert_eq!(c.storage.secondary, vec!["s3-backup".to_string()]);
        assert_eq!(c.storage.backends.len(), 2);
    }
}

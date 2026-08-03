//! App state: where config-sync's files live and how they're loaded/saved.

use crate::CliError;
use cs_config::{Config, StorageConfig, CURRENT_SCHEMA_VERSION};
use cs_keys::{DeviceIdentity, SecretStore};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "config.toml";
const STORE_DIR: &str = "store";
const IDENTITY_ACCOUNT: &str = "device-identity";

/// The on-disk layout of a config-sync installation.
pub struct AppState {
    pub config_dir: PathBuf,
    pub store_dir: PathBuf,
    pub config_path: PathBuf,
    pub prefer_biometrics: bool,
}

/// How the device identity is persisted. Tests use `File` (a plain file in the
/// config dir); production uses `Keyring` (the OS keychain) or `Biometric`
/// (Touch ID / Windows Hello gated keychain).
pub enum AppStore {
    File(FileSecretStore),
    #[cfg(feature = "keyring-store")]
    Keyring(cs_keys::KeyringStore),
    #[cfg(feature = "biometric")]
    Biometric(cs_keys::BiometricStore),
}

impl AppState {
    /// Resolve the config dir from the CLI override or the platform default.
    /// `prefer_biometrics` selects a biometric-gated store when the feature is
    /// available (ignored otherwise).
    pub fn new(config_dir: Option<PathBuf>, prefer_biometrics: bool) -> Result<Self, CliError> {
        let config_dir = match config_dir {
            Some(d) => d,
            None => default_config_dir()?,
        };
        Ok(Self {
            store_dir: config_dir.join(STORE_DIR),
            config_path: config_dir.join(CONFIG_FILE),
            config_dir,
            prefer_biometrics,
        })
    }

    /// For tests: place everything under a temp dir.
    pub fn for_test(root: &Path) -> Self {
        Self {
            config_dir: root.to_path_buf(),
            store_dir: root.join(STORE_DIR),
            config_path: root.join(CONFIG_FILE),
            prefer_biometrics: false,
        }
    }

    pub fn config_exists(&self) -> bool {
        self.config_path.exists()
    }

    pub fn identity_exists(&self, store: &AppStore) -> bool {
        store.get(IDENTITY_ACCOUNT).is_ok()
    }

    pub fn load_config(&self) -> Result<Config, CliError> {
        if !self.config_path.exists() {
            return Err(CliError::Plain(format!(
                "no config found at {}; run `config-sync init` first",
                self.config_path.display()
            )));
        }
        Ok(Config::from_path(&self.config_path)?)
    }

    pub fn save_config(&self, cfg: &Config) -> Result<(), CliError> {
        if let Some(parent) = self.config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(cfg)
            .map_err(|e| CliError::Plain(format!("config serialize: {e}")))?;
        std::fs::write(&self.config_path, s)?;
        Ok(())
    }

    /// Build the default starter config for a freshly initialized device.
    pub fn starter_config(host: &str) -> Config {
        Config {
            schema_version: CURRENT_SCHEMA_VERSION,
            identity: cs_config::Identity {
                device_id: short_device_id(host),
            },
            configs: Vec::new(),
            storage: StorageConfig {
                primary: "local".to_string(),
                secondary: Vec::new(),
                backends: vec![cs_config::Backend {
                    name: "local".to_string(),
                    kind: "local-fs".to_string(),
                    opts: std::collections::BTreeMap::new(),
                }],
            },
        }
    }

    pub fn secret_store(&self) -> AppStore {
        // Prefer the biometric-gated store when the feature is on and the user
        // hasn't opted out with --no-biometrics.
        #[cfg(feature = "biometric")]
        if self.prefer_biometrics {
            return AppStore::Biometric(cs_keys::BiometricStore::new("config-sync"));
        }
        #[cfg(feature = "keyring-store")]
        {
            return AppStore::Keyring(cs_keys::KeyringStore::new("config-sync"));
        }
        #[allow(unreachable_code)]
        AppStore::File(FileSecretStore::new(self.config_dir.join("identity.bin")))
    }

    pub fn load_identity(&self, store: &AppStore) -> Result<DeviceIdentity, CliError> {
        let bytes = store.get(IDENTITY_ACCOUNT).map_err(|_| {
            CliError::Plain("no device identity found; run `config-sync init`".into())
        })?;
        let id = cs_keys::load_identity_from_bytes(&bytes)
            .map_err(|e| CliError::Plain(format!("identity decode: {e}")))?;
        Ok(id)
    }

    pub fn store_identity(&self, store: &AppStore, id: &DeviceIdentity) -> Result<(), CliError> {
        let bytes = cs_keys::identity_to_bytes(id)
            .map_err(|e| CliError::Plain(format!("identity encode: {e}")))?;
        store.put(IDENTITY_ACCOUNT, &bytes)?;
        Ok(())
    }

    /// Read every managed file's on-disk path for this device, resolving the
    /// logical config path via cs-config's PathResolver.
    pub fn managed_files(
        &self,
        cfg: &Config,
        platform: cs_config::Platform,
        home: &str,
        host: &str,
    ) -> Result<Vec<cs_sync::ManagedFile>, CliError> {
        let mut out = Vec::new();
        for set in &cfg.configs {
            let policy = set.conflict_policy;
            if let Some(loc) = pick_location(&set.locations, platform, host) {
                let disk = cs_config::resolve(&loc.path, platform, home)?;
                let logical = cs_manifest::ConfigPath::new(format!(
                    "{}/{}",
                    set.name,
                    file_name_of(&loc.path)
                ));
                out.push(cs_sync::ManagedFile {
                    logical,
                    disk_path: disk,
                    policy,
                });
            }
        }
        Ok(out)
    }
}

/// Pick the location whose host matches exactly, else one matching this
/// platform, else a generic (any-host/any-platform), else the first.
fn pick_location<'a>(
    locations: &'a [cs_config::Location],
    platform: cs_config::Platform,
    host: &str,
) -> Option<&'a cs_config::Location> {
    let plat_str = platform_to_str(platform);
    locations
        .iter()
        .find(|l| !l.host.is_empty() && l.host == host)
        .or_else(|| {
            locations
                .iter()
                .find(|l| !l.platform.is_empty() && l.platform == plat_str)
        })
        .or_else(|| {
            locations
                .iter()
                .find(|l| l.host.is_empty() && l.platform.is_empty())
        })
        .or_else(|| locations.first())
}

pub fn platform_to_str(p: cs_config::Platform) -> &'static str {
    match p {
        cs_config::Platform::Mac => "mac",
        cs_config::Platform::Windows => "windows",
        cs_config::Platform::Linux => "linux",
        cs_config::Platform::FreeBSD => "freebsd",
    }
}

fn file_name_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string())
}

pub fn short_device_id(host: &str) -> String {
    let mut buf = [0u8; 4];
    let _ = getrandom::fill(&mut buf);
    format!("{host}-{}", hex::encode(buf))
}

fn default_config_dir() -> Result<PathBuf, CliError> {
    dirs::config_dir()
        .map(|d| d.join("config-sync"))
        .ok_or_else(|| CliError::Plain("could not determine config dir for this platform".into()))
}

/// A trivially simple file-backed secret store for tests / non-keyring builds.
pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> std::collections::HashMap<String, Vec<u8>> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, map: &std::collections::HashMap<String, Vec<u8>>) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = postcard::to_allocvec(map) {
            let _ = std::fs::write(&self.path, bytes);
        }
    }
}

impl SecretStore for FileSecretStore {
    fn put(&self, account: &str, secret: &[u8]) -> Result<(), cs_keys::KeysError> {
        let mut map = self.load();
        map.insert(account.to_string(), secret.to_vec());
        self.save(&map);
        Ok(())
    }
    fn get(&self, account: &str) -> Result<Vec<u8>, cs_keys::KeysError> {
        self.load()
            .get(account)
            .cloned()
            .ok_or(cs_keys::KeysError::NotFound)
    }
    fn delete(&self, account: &str) -> Result<(), cs_keys::KeysError> {
        let mut map = self.load();
        map.remove(account).ok_or(cs_keys::KeysError::NotFound)?;
        self.save(&map);
        Ok(())
    }
}

impl AppStore {
    pub fn put(&self, account: &str, secret: &[u8]) -> Result<(), CliError> {
        match self {
            AppStore::File(f) => f.put(account, secret)?,
            #[cfg(feature = "keyring-store")]
            AppStore::Keyring(k) => k.put(account, secret)?,
            #[cfg(feature = "biometric")]
            AppStore::Biometric(b) => b.put(account, secret)?,
        }
        Ok(())
    }
    pub fn get(&self, account: &str) -> Result<Vec<u8>, CliError> {
        match self {
            AppStore::File(f) => f.get(account).map_err(CliError::from),
            #[cfg(feature = "keyring-store")]
            AppStore::Keyring(k) => k.get(account).map_err(CliError::from),
            #[cfg(feature = "biometric")]
            AppStore::Biometric(b) => b.get(account).map_err(CliError::from),
        }
    }
}

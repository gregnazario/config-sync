//! OS keychain-backed [`SecretStore`], behind the `keyring` feature.
//!
//! On macOS this maps to the Keychain; on Windows to Credential Manager; on
//! Linux/FreeBSD to the Secret Service (GNOME Keyring / KWallet) when the
//! appropriate `keyring` backend feature is enabled. Biometric gating is a
//! property of how the platform item is created and is configured per-OS at
//! a higher layer; this store simply reads/writes the secret bytes.

use crate::error::KeysError;
use crate::SecretStore;
use base64::{engine::general_purpose::STANDARD, Engine as _};

pub struct KeyringStore {
    pub service: String,
}

impl KeyringStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry, KeysError> {
        keyring::Entry::new(&self.service, account).map_err(|e| KeysError::Keychain(e.to_string()))
    }
}

impl SecretStore for KeyringStore {
    fn put(&self, account: &str, secret: &[u8]) -> Result<(), KeysError> {
        let b64 = STANDARD.encode(secret);
        self.entry(account)?
            .set_password(&b64)
            .map_err(|e| KeysError::Keychain(e.to_string()))
    }

    fn get(&self, account: &str) -> Result<Vec<u8>, KeysError> {
        let s = self.entry(account)?.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => KeysError::NotFound,
            other => KeysError::Keychain(other.to_string()),
        })?;
        STANDARD
            .decode(s)
            .map_err(|e| KeysError::Keychain(format!("base64 decode: {e}")))
    }

    fn delete(&self, account: &str) -> Result<(), KeysError> {
        match self.entry(account)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Err(KeysError::NotFound),
            Err(e) => Err(KeysError::Keychain(e.to_string())),
        }
    }
}

// Keychain behavior is OS-specific and may prompt or require a session, so we
// do not assert against the live OS keychain in CI. The smoke test below is a
// compile-only sanity check; enable the `keyring` feature on a dev machine to
// exercise the real keychain.
#[cfg(all(test, feature = "keyring"))]
mod tests {
    use super::*;

    #[test]
    fn keyring_store_constructs() {
        let _ = KeyringStore::new("config-sync-test");
    }
}

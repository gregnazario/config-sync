//! config-sync key management: secret stores, device identity, recovery providers.

#![forbid(unsafe_code)]

mod error;
mod secret_store;

#[cfg(feature = "keyring")]
mod keyring_store;

pub use error::KeysError;
pub use secret_store::{InMemoryStore, SecretStore};

#[cfg(feature = "keyring")]
pub use keyring_store::KeyringStore;

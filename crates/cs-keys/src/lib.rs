//! config-sync key management: secret stores, device identity, recovery providers.

#![forbid(unsafe_code)]

mod error;
mod identity;
mod recovery;
mod secret_store;

#[cfg(feature = "keyring")]
mod keyring_store;

#[cfg(feature = "biometric")]
mod biometric_store;

pub use error::KeysError;
pub use identity::{
    identity_to_bytes, load_identity, load_identity_from_bytes, store_identity, DeviceIdentity,
};
pub use recovery::{
    rik_fingerprint, CloudBundleProvider, MnemonicProvider, RecoveryBundle, RecoveryKind,
    RecoveryProvider, ShamirProvider, ShamirShare, SplitShares,
};
pub use secret_store::{InMemoryStore, SecretStore};

#[cfg(feature = "keyring")]
pub use keyring_store::KeyringStore;

#[cfg(feature = "biometric")]
pub use biometric_store::BiometricStore;

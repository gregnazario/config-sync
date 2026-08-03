//! Recovery providers: pluggable mechanisms that seal (and recover) the root
//! identity key (RIK) so a user can regain access after losing all devices.
//!
//! Three implementations are provided:
//! - [`mnemonic::MnemonicProvider`] — offline BIP-39 24-word recovery key.
//! - [`shamir::ShamirProvider`] — Shamir k-of-n secret sharing.
//! - [`cloud::CloudBundleProvider`] — Argon2id-from-passphrase bundle uploaded
//!   to a remote store.
//!
//! All providers seal the *same* RIK, so a user may enable more than one.

use crate::error::KeysError;
use serde::{Deserialize, Serialize};

pub mod cloud;
pub mod mnemonic;
pub mod shamir;

pub use cloud::CloudBundleProvider;
pub use mnemonic::MnemonicProvider;
pub use shamir::ShamirProvider;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecoveryKind {
    Mnemonic,
    Shamir { k: u8, n: u8 },
    CloudBundle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryBundle {
    pub kind: RecoveryKind,
    pub payload: Vec<u8>,
}

pub trait RecoveryProvider {
    fn seal(&self, rik: &[u8; 32]) -> Result<RecoveryBundle, KeysError>;
    fn recover(&self, bundle: &RecoveryBundle) -> Result<[u8; 32], KeysError>;
    fn kind(&self) -> RecoveryKind;
}

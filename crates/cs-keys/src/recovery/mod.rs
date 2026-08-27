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
pub use shamir::{ShamirProvider, ShamirShare, SplitShares};

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

/// A short human-comparable fingerprint of the RIK (first 8 bytes of a
/// domain-separated SHA-256, hex-encoded, e.g. `3f9a07c1b2d84e55`).
///
/// Shown to the user when recovery material is created and again when an
/// identity is recovered: if the two don't match, the recovered key came from
/// substituted/tampered shares and must not be trusted. This out-of-band
/// comparison is the only way to detect share substitution — an attacker who
/// controls a full threshold of stored shares can fabricate a self-consistent
/// replacement vault, but cannot make its fingerprint match the one the user
/// recorded.
pub fn rik_fingerprint(rik: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"csync/rik-fingerprint/v1");
    h.update(rik);
    let out = h.finalize();
    hex::encode(&out[..8])
}

pub trait RecoveryProvider {
    fn seal(&self, rik: &[u8; 32]) -> Result<RecoveryBundle, KeysError>;
    fn recover(&self, bundle: &RecoveryBundle) -> Result<[u8; 32], KeysError>;
    fn kind(&self) -> RecoveryKind;
}

//! config-sync crypto core: hybrid PQ+classic KEM, per-file DEK, AEAD envelope.
//!
//! This crate has NO I/O dependencies. It accepts and returns bytes only.

#![forbid(unsafe_code)]

mod aad;
mod envelope;
mod error;
mod kem;
mod keys;
mod manifest_sig;
mod wrap;

pub use aad::Aad;
pub use envelope::{open, seal, OpenInput, SealOutput, MAGIC, VERSION};
pub use error::CryptoError;
pub use kem::{
    derive_recipient_keypair, generate_recipient_keypair, hybrid_decapsulate, hybrid_encapsulate,
    HybridKemCt, RecipientKeys, RecipientSecrets,
};
pub use keys::{generate_dek, generate_mk, generate_rik, Dek, Mk, Rik};
pub use manifest_sig::{
    verify_manifest_signature, ManifestSigningKey, MANIFEST_SIG_LEN, MANIFEST_VERIFYING_KEY_LEN,
};
pub use wrap::{unwrap_key, wrap_key, WrappedKey};

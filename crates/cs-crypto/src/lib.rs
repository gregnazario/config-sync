//! config-sync crypto core: hybrid PQ+classic KEM, per-file DEK, AEAD envelope.
//!
//! This crate has NO I/O dependencies. It accepts and returns bytes only.

#![forbid(unsafe_code)]

mod aad;
mod error;
mod keys;

pub use aad::Aad;
pub use error::CryptoError;
pub use keys::{generate_dek, generate_mk, generate_rik, Dek, Mk, Rik};

//! config-sync crypto core: hybrid PQ+classic KEM, per-file DEK, AEAD envelope.
//!
//! This crate has NO I/O dependencies. It accepts and returns bytes only.

#![forbid(unsafe_code)]

mod aad;
mod error;

pub use aad::Aad;
pub use error::CryptoError;

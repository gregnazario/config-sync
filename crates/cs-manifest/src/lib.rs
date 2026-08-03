//! Versioned sync manifest: per-path vector clocks, entries, resolution records.
//!
//! Pure data structures and algorithms — no I/O.

#![forbid(unsafe_code)]

mod clock;
mod entry;
mod error;
mod manifest;
mod types;

pub use clock::VectorClock;
pub use entry::{Entry, ResolutionRecord};
pub use error::ManifestError;
pub use manifest::{Manifest, MANIFEST_SCHEMA_VERSION};
pub use types::{ConfigPath, DeviceId, Sha256};

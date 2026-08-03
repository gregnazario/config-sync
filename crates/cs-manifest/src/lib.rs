//! Versioned sync manifest: per-path vector clocks, entries, resolution records.
//!
//! Pure data structures and algorithms — no I/O.

#![forbid(unsafe_code)]

mod clock;
mod types;

pub use clock::VectorClock;
pub use types::{ConfigPath, DeviceId, Sha256};

//! config-sync engine: pull/diff/apply/push with conflict resolution.

#![forbid(unsafe_code)]

mod diff;
mod error;

pub use diff::{diff, DiffOp};
pub use error::SyncError;

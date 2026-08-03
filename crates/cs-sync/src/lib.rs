//! config-sync engine: pull/diff/apply/push with conflict resolution.

#![forbid(unsafe_code)]

mod conflict;
mod diff;
mod error;
mod local_io;

pub use conflict::{
    make_record, resolve_conflict, Conflict, ConflictChoice, ConflictResolver, FixedResolver,
    Resolution,
};
pub use diff::{diff, DiffOp};
pub use error::SyncError;
pub use local_io::{open_sealed, read_and_seal, write_plaintext, SealedFile};

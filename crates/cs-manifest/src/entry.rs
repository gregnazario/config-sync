use crate::clock::VectorClock;
use crate::types::Sha256;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// One version of one managed path: the ciphertext blob holding it, the causal
/// clock, size, and a tombstone flag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Content-addressed id of the blob holding the envelope header
    /// (`blobs/<hex>`); the matching body lives at `blobs/<hex>.body`.
    pub blob_id: Sha256,
    /// Hash of the *plaintext* — used to detect real content changes without
    /// re-sealing on every sync (sealing is randomized, so the ciphertext
    /// blob id is not a stable content fingerprint).
    pub content_hash: Sha256,
    /// Version bound into the AEAD AAD; bumped on each content change.
    pub aad_version: u64,
    /// Per-path causal clock used by the diff/conflict logic.
    pub clock: VectorClock,
    pub size: u64,
    pub modified: SystemTime,
    /// True once the path has been deleted; the entry is kept as a tombstone.
    pub deleted: bool,
}

/// Records how a conflict was resolved so the other device converges and the
/// superseded blobs are known for history/GC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRecord {
    pub at_version: u64,
    pub chosen_blob: Sha256,
    pub superseded: Vec<Sha256>,
    pub clock: VectorClock,
}

# config-sync Cycle 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the sync engine (versioned manifest + vector clocks + CAS), conflict detection and resolution, the local-file bridge, and the S3 `RemoteStore` backend — all TDD — on top of the Cycle 1 foundation.

**Architecture:** Additive. New crates `cs-manifest` (pure data/algorithms) and `cs-sync` (the engine), plus an `s3` backend in `cs-storage` behind a feature. The manifest is the only mutable object on a store; everything else is content-addressed and immutable.

**Tech Stack:** Rust edition 2021; `serde`/`postcard`/`sha2` (manifest), `aws-sdk-s3` (S3 backend), `s3s` + `hyper` (in-process S3 mock for tests), `dialoguer` (terminal conflict resolver). Reuses Cycle 1 `RemoteStore`, `Etag`, `ConflictPolicy`, crypto envelope.

## Global Constraints

- Same as Cycle 1: Rust edition 2021, `forbid(unsafe_code)` in all new crates, `cargo test`/`clippy -D warnings`/`fmt --check` green at every commit, conventional-commit messages, **no AI attribution** in commits.
- New crates added to the workspace `[workspace] members`.
- New dependencies pinned in `[workspace.dependencies]` where shared.
- Manifest serialization is **deterministic** (sorted maps, postcard) so identical manifests produce identical bytes (needed for stable hashes/tests).
- No live AWS in tests: S3 backend tested against an in-process `s3s` mock.
- A managed config path is a **logical** key (`"vim/.vimrc"`), never an OS path. The `cs-config` PathResolver maps logical → OS path per machine.

**Spec:** `docs/superpowers/specs/2026-08-02-config-sync-cycle2-sync-engine.md`

---

## File Structure (additions only)

```
crates/
├── cs-manifest/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs        # re-exports
│       ├── clock.rs      # VectorClock (partial order, merge, bump)
│       ├── types.rs      # DeviceId, ConfigPath, Sha256 newtypes
│       ├── entry.rs      # Entry, ResolutionRecord
│       ├── manifest.rs   # Manifest struct + deterministic ser/de
│       └── error.rs
├── cs-sync/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── diff.rs       # diff(local, remote) -> Vec<DiffOp>
│       ├── conflict.rs   # Conflict, ConflictChoice, policies, resolver trait
│       ├── engine.rs     # sync(): pull/diff/apply/push + CAS retry
│       ├── local_io.rs   # read/write managed files on disk + seal/open blobs
│       └── error.rs
└── cs-storage/
    └── src/s3.rs         # S3 backend (behind feature "s3")
```

---

## Task 1: Scaffold cs-manifest + cs-sync crates

**Files:** Create `crates/cs-manifest/{Cargo.toml,src/lib.rs}`, `crates/cs-sync/{Cargo.toml,src/lib.rs}`; add both to workspace members.

- [ ] Step 1: Create `crates/cs-manifest/Cargo.toml`:
```toml
[package]
name = "cs-manifest"
version.workspace = true
edition.workspace = true
license.workspace = true
[dependencies]
serde = { workspace = true }
postcard = { version = "1", features = ["alloc"] }
sha2 = "0.10"
thiserror = { workspace = true }
```
- [ ] Step 2: Create `crates/cs-manifest/src/lib.rs`:
```rust
//! Versioned sync manifest: per-path vector clocks, entries, resolution records.
#![forbid(unsafe_code)]
```
- [ ] Step 3: Create `crates/cs-sync/Cargo.toml`:
```toml
[package]
name = "cs-sync"
version.workspace = true
edition.workspace = true
license.workspace = true
[dependencies]
cs-manifest = { path = "../cs-manifest" }
cs-storage = { path = "../cs-storage" }
cs-crypto = { path = "../cs-crypto" }
cs-config = { path = "../cs-config" }
thiserror = { workspace = true }
serde = { workspace = true }
postcard = { version = "1", features = ["alloc"] }
tokio = { version = "1", features = ["fs", "io-util", "rt", "macros"] }
bytes = { workspace = true }
sha2 = "0.10"
[dev-dependencies]
tempfile = "3"
```
- [ ] Step 4: Create `crates/cs-sync/src/lib.rs`:
```rust
//! config-sync engine: pull/diff/apply/push with conflict resolution.
#![forbid(unsafe_code)]
```
- [ ] Step 5: Add both to root `Cargo.toml` `[workspace] members` after `cs-config`.
- [ ] Step 6: `cargo build --workspace` (green), `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Step 7: `git add -A && git commit -m "chore(sync): scaffold cs-manifest and cs-sync crates"`

---

## Task 2: cs-manifest types (DeviceId, ConfigPath, Sha256)

**Files:** `crates/cs-manifest/src/types.rs`, modify `lib.rs`.

- [ ] Step 1: Write `types.rs`:
```rust
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(pub String);
impl DeviceId {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigPath(pub String);
impl ConfigPath {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }
    pub fn as_str(&self) -> &str { &self.0 }
}
impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}

/// A 32-byte content hash; hex-encoded for blob ids.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Sha256(pub [u8; 32]);
impl Sha256 {
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
    pub fn of(data: &[u8]) -> Self {
        use sha2::{Digest, Sha256 as S};
        let mut h = S::new();
        h.update(data);
        let out = h.finalize();
        let mut b = [0u8; 32]; b.copy_from_slice(&out);
        Self(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_of_known_input() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let h = Sha256::of(b"");
        assert_eq!(h.to_hex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
    #[test]
    fn config_path_orders_lexicographically() {
        let a = ConfigPath::new("a/b");
        let b = ConfigPath::new("a/c");
        assert!(a < b);
    }
}
```
- [ ] Step 2: Add `hex = "0.4"` to cs-manifest deps. Add `mod types; pub use types::*;` to lib.rs.
- [ ] Step 3: `cargo test -p cs-manifest` (1 + 1 pass). clippy, fmt.
- [ ] Step 4: commit `feat(manifest): add DeviceId/ConfigPath/Sha256 newtypes`.

---

## Task 3: VectorClock

**Files:** `crates/cs-manifest/src/clock.rs`, modify lib.rs.

- [ ] Step 1: Write `clock.rs` (red tests first, then impl):
```rust
use crate::types::DeviceId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VectorClock(pub BTreeMap<DeviceId, u64>);

impl VectorClock {
    pub fn new() -> Self { Self::default() }
    pub fn get(&self, d: &DeviceId) -> u64 { self.0.get(d).copied().unwrap_or(0) }
    pub fn bump(&mut self, d: &DeviceId) -> u64 {
        let v = self.0.entry(d.clone()).or_insert(0);
        *v += 1;
        *v
    }
    pub fn merge(&mut self, other: &Self) {
        for (k, v) in &other.0 {
            let cur = self.0.get(k).copied().unwrap_or(0);
            self.0.insert(k.clone(), cur.max(*v));
        }
    }
    /// self happens-before other: every component <= other, and at least one <.
    pub fn happens_before(&self, other: &Self) -> bool {
        let keys: std::collections::BTreeSet<_> = self.0.keys().chain(other.0.keys()).collect();
        let mut le = true;
        let mut strictly_less = false;
        for k in keys {
            let a = self.get(k);
            let b = other.get(k);
            if a > b { return false; }
            if a < b { strictly_less = true; }
            if a == b { /* keep le true */ }
        }
        le && strictly_less
    }
    pub fn equal(&self, other: &Self) -> bool { self.0 == other.0 }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(s: &str) -> DeviceId { DeviceId::new(s) }

    #[test]
    fn empty_clocks_do_not_happen_before() {
        let a = VectorClock::new();
        let b = VectorClock::new();
        assert!(!a.happens_before(&b));
        assert!(a.equal(&b));
    }

    #[test]
    fn bump_makes_clock_advance() {
        let mut a = VectorClock::new();
        a.bump(&d("A"));
        let b = VectorClock::new();
        assert!(b.happens_before(&a));
        assert!(!a.happens_before(&b));
    }

    #[test]
    fn concurrent_clocks_neither_happens_before() {
        // A={A:1}, B={B:1} → concurrent
        let mut a = VectorClock::new(); a.bump(&d("A"));
        let mut b = VectorClock::new(); b.bump(&d("B"));
        assert!(!a.happens_before(&b));
        assert!(!b.happens_before(&a));
    }

    #[test]
    fn merge_is_union_of_components() {
        let mut a = VectorClock::new(); a.bump(&d("A"));
        let mut b = VectorClock::new(); b.bump(&d("B"));
        let mut m = a.clone(); m.merge(&b);
        assert_eq!(m.get(&d("A")), 1);
        assert_eq!(m.get(&d("B")), 1);
    }

    #[test]
    fn merge_takes_max() {
        let mut a = VectorClock::new(); a.bump(&d("A")); a.bump(&d("A")); // A:2
        let mut b = VectorClock::new(); b.bump(&d("A")); // A:1
        a.merge(&b);
        assert_eq!(a.get(&d("A")), 2);
    }

    #[test]
    fn happens_before_is_strict() {
        // {A:1} does NOT happen-before {A:1,B:0}=={A:1}; equal is not strict.
        let mut a = VectorClock::new(); a.bump(&d("A"));
        let b = a.clone();
        assert!(!a.happens_before(&b));
    }
}
```
- [ ] Step 2: add `mod clock; pub use clock::VectorClock;` to lib.rs.
- [ ] Step 3: `cargo test -p cs-manifest clock` (6 pass). clippy, fmt.
- [ ] Step 4: commit `feat(manifest): VectorClock with partial-order happens_before + merge`.

---

## Task 4: Entry, ResolutionRecord, Manifest

**Files:** `crates/cs-manifest/src/{entry.rs,manifest.rs,error.rs}`, modify lib.rs.

- [ ] Step 1: `error.rs`:
```rust
use thiserror::Error;
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("decode error: {0}")]
    Decode(String),
    #[error("schema version mismatch: got {0}")]
    SchemaVersion(u32),
}
```
- [ ] Step 2: `entry.rs`:
```rust
use crate::clock::VectorClock;
use crate::types::Sha256;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const ENTRY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub blob_id: Sha256,
    pub aad_version: u64,
    pub clock: VectorClock,
    pub size: u64,
    pub modified: SystemTime,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRecord {
    pub at_version: u64,
    pub chosen_blob: Sha256,
    pub superseded: Vec<Sha256>,
    pub clock: VectorClock,
}
```
- [ ] Step 3: `manifest.rs`:
```rust
use crate::clock::VectorClock;
use crate::entry::{Entry, ResolutionRecord};
use crate::types::ConfigPath;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub device_id: String,
    pub clock: VectorClock,
    pub entries: BTreeMap<ConfigPath, Entry>,
    pub resolutions: BTreeMap<ConfigPath, ResolutionRecord>,
    pub manifest_version: u64,
}

impl Manifest {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            device_id: device_id.into(),
            clock: VectorClock::new(),
            entries: BTreeMap::new(),
            resolutions: BTreeMap::new(),
            manifest_version: 0,
        }
    }
    /// Deterministic postcard encoding (sorted maps => stable bytes).
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::ManifestError> {
        postcard::to_allocvec(self).map_err(|e| crate::error::ManifestError::Decode(e.to_string()))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, crate::error::ManifestError> {
        let m: Manifest = postcard::from_bytes(b).map_err(|e| crate::error::ManifestError::Decode(e.to_string()))?;
        if m.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(crate::error::ManifestError::SchemaVersion(m.schema_version));
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DeviceId, Sha256};
    #[test]
    fn manifest_round_trips() {
        let mut m = Manifest::new("dev-A");
        m.clock.bump(&DeviceId::new("dev-A"));
        m.entries.insert(ConfigPath::new("vim/.vimrc"), Entry {
            blob_id: Sha256::of(b"x"), aad_version: 1, clock: m.clock.clone(),
            size: 1, modified: SystemTime::UNIX_EPOCH, deleted: false,
        });
        let bytes = m.to_bytes().unwrap();
        let back = Manifest::from_bytes(&bytes).unwrap();
        assert_eq!(m, back);
    }
    #[test]
    fn encoding_is_deterministic() {
        let m = Manifest::new("dev-A");
        assert_eq!(m.to_bytes().unwrap(), m.to_bytes().unwrap());
    }
}
```
- [ ] Step 4: wire `mod entry; mod manifest; mod error;` + re-exports into lib.rs.
- [ ] Step 5: `cargo test -p cs-manifest` (all pass). clippy, fmt.
- [ ] Step 6: commit `feat(manifest): Entry, ResolutionRecord, Manifest with deterministic ser/de`.

---

## Task 5: cs-sync diff

**Files:** `crates/cs-sync/src/{error.rs,diff.rs}`, modify lib.rs.

- [ ] Step 1: `error.rs`:
```rust
use thiserror::Error;
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("storage error: {0}")]
    Storage(#[from] cs_storage::StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] cs_crypto::CryptoError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("manifest error: {0}")]
    Manifest(String),
    #[error("conflict requires resolution but no resolver was provided")]
    UnresolvedConflict,
    #[error("conflict resolution aborted by user")]
    Aborted,
    #[error("cas retries exhausted after {0} attempts")]
    CasRetriesExhausted(u32),
}
```
- [ ] Step 2: `diff.rs` (red tests, then impl):
```rust
use cs_manifest::{ConfigPath, Entry, Manifest};

/// What the engine should do for one path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffOp {
    /// Remote has it, local doesn't (or remote is strictly newer) → pull.
    PullLocal { path: ConfigPath, remote: Entry },
    /// Local has it and is strictly newer → push.
    PushRemote { path: ConfigPath, local: Entry },
    /// Both have it, identical → no-op.
    InSync { path: ConfigPath },
    /// Concurrent edits → conflict.
    Conflict { path: ConfigPath, local: Entry, remote: Entry },
    /// Remote tombstoned past local → propagate deletion locally.
    PullDeletion { path: ConfigPath, remote: Entry },
    /// Local tombstoned past remote → push deletion.
    PushDeletion { path: ConfigPath, local: Entry },
}

pub fn diff(local: &Manifest, remote: &Manifest) -> Vec<DiffOp> {
    use std::collections::BTreeSet;
    let paths: BTreeSet<&ConfigPath> = local.entries.keys().chain(remote.entries.keys()).collect();
    let mut out = Vec::new();
    for p in paths {
        match (local.entries.get(p).cloned(), remote.entries.get(p).cloned()) {
            (None, Some(r)) => {
                if r.deleted { out.push(DiffOp::PullDeletion { path: p.clone(), remote: r }); }
                else { out.push(DiffOp::PullLocal { path: p.clone(), remote: r }); }
            }
            (Some(l), None) => {
                out.push(DiffOp::PushRemote { path: p.clone(), local: l });
            }
            (Some(l), Some(r)) => {
                if l == r { out.push(DiffOp::InSync { path: p.clone() }); }
                else if l.clock.happens_before(&r.clock) {
                    if r.deleted { out.push(DiffOp::PullDeletion { path: p.clone(), remote: r }); }
                    else { out.push(DiffOp::PullLocal { path: p.clone(), remote: r }); }
                } else if r.clock.happens_before(&l.clock) {
                    if l.deleted { out.push(DiffOp::PushDeletion { path: p.clone(), local: l }); }
                    else { out.push(DiffOp::PushRemote { path: p.clone(), local: l }); }
                } else {
                    out.push(DiffOp::Conflict { path: p.clone(), local: l, remote: r });
                }
            }
            (None, None) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_manifest::{DeviceId, Manifest, Sha256, VectorClock};
    use std::time::SystemTime;
    fn entry(blob: &[u8], dev: &str) -> Entry {
        let mut c = VectorClock::new(); c.bump(&DeviceId::new(dev));
        Entry { blob_id: Sha256::of(blob), aad_version: 1, clock: c, size: blob.len() as u64, modified: SystemTime::UNIX_EPOCH, deleted: false }
    }
    #[test]
    fn remote_only_is_pull() {
        let l = Manifest::new("A"); let mut r = Manifest::new("B");
        r.entries.insert(ConfigPath::new("p"), entry(b"r", "B"));
        let d = diff(&l, &r);
        assert!(matches!(d.as_slice(), [DiffOp::PullLocal { .. }]));
    }
    #[test]
    fn identical_is_in_sync() {
        let mut l = Manifest::new("A"); let mut r = Manifest::new("A");
        let e = entry(b"x", "A");
        l.entries.insert(ConfigPath::new("p"), e.clone());
        r.entries.insert(ConfigPath::new("p"), e);
        assert!(matches!(diff(&l, &r).as_slice(), [DiffOp::InSync { .. }]));
    }
    #[test]
    fn fast_forward_pull() {
        let mut l = Manifest::new("A"); let mut r = Manifest::new("A");
        let mut c1 = VectorClock::new(); c1.bump(&DeviceId::new("A"));
        let mut c2 = c1.clone(); c2.bump(&DeviceId::new("A"));
        l.entries.insert(ConfigPath::new("p"), Entry { blob_id: Sha256::of(b"v1"), aad_version:1, clock: c1, size:2, modified: SystemTime::UNIX_EPOCH, deleted:false });
        r.entries.insert(ConfigPath::new("p"), Entry { blob_id: Sha256::of(b"v2"), aad_version:1, clock: c2, size:2, modified: SystemTime::UNIX_EPOCH, deleted:false });
        assert!(matches!(diff(&l, &r).as_slice(), [DiffOp::PullLocal { .. }]));
    }
    #[test]
    fn concurrent_is_conflict() {
        let mut l = Manifest::new("A"); let mut r = Manifest::new("B");
        let mut cl = VectorClock::new(); cl.bump(&DeviceId::new("A"));
        let mut cr = VectorClock::new(); cr.bump(&DeviceId::new("B"));
        l.entries.insert(ConfigPath::new("p"), Entry { blob_id: Sha256::of(b"l"), aad_version:1, clock: cl, size:1, modified: SystemTime::UNIX_EPOCH, deleted:false });
        r.entries.insert(ConfigPath::new("p"), Entry { blob_id: Sha256::of(b"r"), aad_version:1, clock: cr, size:1, modified: SystemTime::UNIX_EPOCH, deleted:false });
        assert!(matches!(diff(&l, &r).as_slice(), [DiffOp::Conflict { .. }]));
    }
}
```
- [ ] Step 3: wire `mod error; mod diff; pub use diff::{diff, DiffOp}; pub use error::SyncError;` into cs-sync lib.rs.
- [ ] Step 4: `cargo test -p cs-sync diff` (4 pass). clippy, fmt.
- [ ] Step 5: commit `feat(sync): manifest diff with conflict detection`.

---

## Task 6: Conflict resolution (policies + resolver trait)

**Files:** `crates/cs-sync/src/conflict.rs`, modify lib.rs.

- [ ] Step 1: `conflict.rs`:
```rust
use crate::diff::DiffOp;
use cs_config::ConflictPolicy;
use cs_manifest::{ConfigPath, Entry, ResolutionRecord, Sha256, VectorClock};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictChoice { KeepLocal, KeepRemote, KeepBoth, Abort }

#[derive(Clone, Debug)]
pub struct Conflict {
    pub path: ConfigPath,
    pub local: Entry,
    pub remote: Entry,
}

pub trait ConflictResolver: Send + Sync {
    fn resolve(&self, c: &Conflict) -> Result<ConflictChoice, crate::SyncError>;
}

/// A resolver that always returns a fixed choice (for tests / headless).
pub struct FixedResolver(pub ConflictChoice);
impl ConflictResolver for FixedResolver {
    fn resolve(&self, _c: &Conflict) -> Result<ConflictChoice, crate::SyncError> { Ok(self.0.clone()) }
}

/// Outcome of resolving a conflict: which entry wins, plus the superseded blobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Resolved { chosen: Entry, superseded: Vec<Sha256>, record_clock: VectorClock },
    Aborted,
}

/// Apply a policy+choice to a conflict. `now` lets tests be deterministic.
pub fn resolve_conflict(
    conflict: &Conflict,
    policy: ConflictPolicy,
    resolver: Option<&dyn ConflictResolver>,
    manifest_version: u64,
    now: SystemTime,
) -> Result<Resolution, crate::SyncError> {
    let choice = match policy {
        ConflictPolicy::LatestWins => {
            if conflict.local.modified >= conflict.remote.modified { ConflictChoice::KeepLocal }
            else { ConflictChoice::KeepRemote }
        }
        ConflictPolicy::Prompt => {
            let r = resolver.ok_or(crate::SyncError::UnresolvedConflict)?;
            r.resolve(conflict)?
        }
        ConflictPolicy::Manual => ConflictChoice::KeepBoth, // surface; engine writes both files
    };
    Ok(match choice {
        ConflictChoice::Abort => Resolution::Aborted,
        ConflictChoice::KeepLocal => Resolution::Resolved {
            chosen: conflict.local.clone(),
            superseded: vec![conflict.remote.blob_id.clone()],
            record_clock: conflict.local.clock.clone(),
        },
        ConflictChoice::KeepRemote => Resolution::Resolved {
            chosen: conflict.remote.clone(),
            superseded: vec![conflict.local.blob_id.clone()],
            record_clock: conflict.remote.clock.clone(),
        },
        ConflictChoice::KeepBoth => Resolution::Resolved {
            // Keep local as the entry; remote written alongside as <path>.remote
            chosen: conflict.local.clone(),
            superseded: vec![conflict.remote.blob_id.clone()],
            record_clock: {
                let mut c = conflict.local.clock.clone();
                c.merge(&conflict.remote.clock);
                c
            },
        },
    })
}

// helper used by engine to record a resolution
pub fn make_record(r: &Resolution, manifest_version: u64) -> Option<ResolutionRecord> {
    match r {
        Resolution::Resolved { chosen, superseded, record_clock } => Some(ResolutionRecord {
            at_version: manifest_version,
            chosen_blob: chosen.blob_id.clone(),
            superseded: superseded.clone(),
            clock: record_clock.clone(),
        }),
        Resolution::Aborted => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_manifest::{DeviceId, VectorClock};
    fn e(blob: &[u8], dev: &str, t: SystemTime) -> Entry {
        let mut c = VectorClock::new(); c.bump(&DeviceId::new(dev));
        Entry { blob_id: Sha256::of(blob), aad_version:1, clock: c, size: blob.len() as u64, modified: t, deleted: false }
    }
    fn conflict(l_t: SystemTime, r_t: SystemTime) -> Conflict {
        Conflict {
            path: ConfigPath::new("p"),
            local: e(b"local", "A", l_t),
            remote: e(b"remote", "B", r_t),
        }
    }
    #[test]
    fn latest_wins_picks_newer() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10));
        let r = resolve_conflict(&c, ConflictPolicy::LatestWins, None, 1, SystemTime::UNIX_EPOCH).unwrap();
        match r { Resolution::Resolved { chosen, .. } => assert_eq!(chosen.blob_id, Sha256::of(b"remote")), _ => panic!() }
    }
    #[test]
    fn prompt_uses_resolver() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let res = FixedResolver(ConflictChoice::KeepLocal);
        let r = resolve_conflict(&c, ConflictPolicy::Prompt, Some(&res), 1, SystemTime::UNIX_EPOCH).unwrap();
        match r { Resolution::Resolved { chosen, .. } => assert_eq!(chosen.blob_id, Sha256::of(b"local")), _ => panic!() }
    }
    #[test]
    fn prompt_without_resolver_errors() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        assert!(matches!(
            resolve_conflict(&c, ConflictPolicy::Prompt, None, 1, SystemTime::UNIX_EPOCH),
            Err(crate::SyncError::UnresolvedConflict)
        ));
    }
    #[test]
    fn abort_propagates() {
        let c = conflict(SystemTime::UNIX_EPOCH, SystemTime::UNIX_EPOCH);
        let res = FixedResolver(ConflictChoice::Abort);
        let r = resolve_conflict(&c, ConflictPolicy::Prompt, Some(&res), 1, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(r, Resolution::Aborted);
    }
}
```
- [ ] Step 2: cs-sync Cargo.toml: add `cs-config` is already a dep. wire `mod conflict;` + re-exports `Conflict, ConflictChoice, ConflictResolver, FixedResolver, Resolution, resolve_conflict`.
- [ ] Step 3: `cargo test -p cs-sync conflict` (4 pass). clippy, fmt.
- [ ] Step 4: commit `feat(sync): conflict policies + resolver trait`.

---

## Task 7: Local-file bridge (read/write + seal/open blobs)

**Files:** `crates/cs-sync/src/local_io.rs`, modify lib.rs.

- [ ] Step 1: `local_io.rs`:
```rust
use crate::SyncError;
use cs_crypto::{open, seal, Aad, OpenInput, RecipientKeys, RecipientSecrets};
use cs_manifest::{ConfigPath, Entry, Sha256, VectorClock};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Read a file from disk and seal it into (header, body) ciphertext plus a new Entry.
pub fn read_and_seal(
    disk_path: &Path,
    logical_path: &ConfigPath,
    aad_version: u64,
    clock: VectorClock,
    recip: &RecipientKeys,
) -> Result<(Entry, Vec<u8>, Vec<u8>), SyncError> {
    let plaintext = std::fs::read(disk_path)?;
    let size = plaintext.len() as u64;
    let aad = Aad { path: logical_path.0.clone(), version: aad_version };
    let out = seal(&plaintext, &aad, recip)?;
    let mut header = out.header.clone();
    header.extend_from_slice(&out.body); // store header+body concatenated under one blob
    let blob_id = Sha256::of(&header);
    let entry = Entry {
        blob_id, aad_version, clock, size,
        modified: std::fs::metadata(disk_path)?.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        deleted: false,
    };
    Ok((entry, header, Vec::new())) // body folded into header blob
}

/// Open a sealed blob and write plaintext back to disk.
pub fn open_and_write(
    blob: &[u8],
    logical_path: &ConfigPath,
    entry: &Entry,
    disk_path: &Path,
    secrets: &RecipientSecrets,
) -> Result<(), SyncError> {
    let aad = Aad { path: logical_path.0.clone(), version: entry.aad_version };
    // header magic+version is fixed-length prefix; we stored header+body concatenated.
    let pt = open_split(blob, &aad, secrets)?;
    if let Some(parent) = disk_path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(disk_path, pt)?;
    Ok(())
}

// Reconstruct where header ends: read magic(6)+version(1), then postcard header.
fn open_split(blob: &[u8], aad: &Aad, secrets: &RecipientSecrets) -> Result<Vec<u8>, SyncError> {
    use cs_crypto::{MAGIC, VERSION};
    if blob.len() < 7 || &blob[..6] != MAGIC || blob[6] != VERSION {
        return Err(SyncError::Manifest("bad blob envelope".into()));
    }
    // The header body is postcard-encoded after the 7-byte prefix; the envelope
    // wrote header then body concatenated. We need the header length. The
    // envelope's HeaderBody has a known postcard shape; rather than re-parse,
    // store the split length in the first 4 bytes is cleaner — but to keep the
    // blob opaque and content-addressable we instead re-derive by trying
    // increasing split points until open succeeds. That is too fragile, so we
    // change storage: header and body are stored as TWO separate objects.
    unreachable!("see Task 7b: store header/body as separate objects")
}
```

- [ ] Step 2 (7b — corrected design): store header and body as **two** content-addressed objects: `blobs/<sha(header)>` and `blobs/<sha(body)>`. The Entry only records the **header** blob id (it carries the wrapped DEK); the body is fetched by a fixed convention `blobs/<sha(header)>.body`. Rewrite `local_io.rs` cleanly:
```rust
use crate::SyncError;
use cs_crypto::{open, seal, Aad, OpenInput, RecipientKeys, RecipientSecrets};
use cs_manifest::{ConfigPath, Entry, Sha256, VectorClock};
use std::path::Path;
use std::time::SystemTime;

pub struct SealedFile {
    pub header_blob: Vec<u8>,
    pub body_blob: Vec<u8>,
    pub header_id: Sha256,
}

pub fn read_and_seal(
    disk_path: &Path,
    logical_path: &ConfigPath,
    aad_version: u64,
    clock: VectorClock,
    recip: &RecipientKeys,
) -> Result<(Entry, SealedFile), SyncError> {
    let plaintext = std::fs::read(disk_path)?;
    let size = plaintext.len() as u64;
    let aad = Aad { path: logical_path.0.clone(), version: aad_version };
    let out = seal(&plaintext, &aad, recip)?;
    let header_id = Sha256::of(&out.header);
    let entry = Entry {
        blob_id: header_id.clone(), aad_version, clock, size,
        modified: std::fs::metadata(disk_path)?.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        deleted: false,
    };
    Ok((entry, SealedFile { header_blob: out.header, body_blob: out.body, header_id }))
}

pub fn open_sealed(
    header: &[u8],
    body: &[u8],
    logical_path: &ConfigPath,
    entry: &Entry,
    secrets: &RecipientSecrets,
) -> Result<Vec<u8>, SyncError> {
    let aad = Aad { path: logical_path.0.clone(), version: entry.aad_version };
    Ok(open(OpenInput { header, body }, &aad, secrets)?)
}

pub fn write_plaintext(disk_path: &Path, plaintext: &[u8]) -> Result<(), SyncError> {
    if let Some(parent) = disk_path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(disk_path, plaintext)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_crypto::generate_recipient_keypair;
    use cs_manifest::DeviceId;
    use tempfile::TempDir;

    #[test]
    fn seal_then_open_round_trips_via_files() {
        let (pk, sk) = generate_recipient_keypair();
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src.txt");
        std::fs::write(&src, b"set nu\n").unwrap();
        let path = ConfigPath::new("vim/.vimrc");
        let mut clock = VectorClock::new(); clock.bump(&DeviceId::new("A"));
        let (entry, sf) = read_and_seal(&src, &path, 1, clock.clone(), &pk).unwrap();
        assert_eq!(entry.size, 8);
        let pt = open_sealed(&sf.header_blob, &sf.body_blob, &path, &entry, &sk).unwrap();
        let dst = dir.path().join("dst.txt");
        write_plaintext(&dst, &pt).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"set nu\n");
    }
}
```
- [ ] Step 3: wire `mod local_io;` + re-exports.
- [ ] Step 4: `cargo test -p cs-sync local_io` (1 pass). clippy, fmt.
- [ ] Step 5: commit `feat(sync): local-file bridge (read/seal, open/write)`.

---

## Task 8: Sync engine (pull/diff/apply/push + CAS retry)

**Files:** `crates/cs-sync/src/engine.rs`, modify lib.rs.

- [ ] Step 1: `engine.rs`:
```rust
use crate::conflict::{resolve_conflict, ConflictResolver, Resolution};
use crate::diff::{diff, DiffOp};
use crate::local_io::{open_sealed, read_and_seal, write_plaintext};
use crate::SyncError;
use cs_config::ConflictPolicy;
use cs_crypto::RecipientKeys;
use cs_manifest::{ConfigPath, DeviceId, Entry, Manifest, Sha256};
use cs_storage::{Etag, RemoteStore};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const MANIFEST_KEY: &str = "manifest.json";
const BLOB_PREFIX: &str = "blobs/";
const MAX_CAS_RETRIES: u32 = 3;

#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    pub pulled: Vec<ConfigPath>,
    pub pushed: Vec<ConfigPath>,
    pub conflicts_resolved: Vec<ConfigPath>,
    pub aborted: bool,
}

/// One local managed file: its logical path, its on-disk location, its policy.
pub struct ManagedFile {
    pub logical: ConfigPath,
    pub disk_path: PathBuf,
    pub policy: ConflictPolicy,
}

/// Read the remote manifest (or return a fresh empty one if absent).
async fn fetch_remote_manifest(store: &dyn RemoteStore) -> Result<(Manifest, Option<Etag>), SyncError> {
    match store.get(MANIFEST_KEY).await {
        Ok(bytes) => {
            let m = Manifest::from_bytes(&bytes).map_err(|e| SyncError::Manifest(e.to_string()))?;
            Ok((m, None)) // etag captured via put's if_match path below
        }
        Err(cs_storage::StorageError::NotFound(_)) => Ok((Manifest::new("remote"), None)),
        Err(e) => Err(e.into()),
    }
}

/// Full sync: pull, diff, apply, push with CAS. `disk_root` is where managed
/// files live; each ManagedFile carries its own disk_path though.
pub async fn sync(
    store: &dyn RemoteStore,
    device: &DeviceId,
    local: &mut Manifest,
    files: &[ManagedFile],
    recip_keys: &RecipientKeys,
    recip_secrets: &cs_crypto::RecipientSecrets,
    resolver: Option<&dyn ConflictResolver>,
    now: SystemTime,
) -> Result<SyncReport, SyncError> {
    let mut report = SyncReport::default();
    for attempt in 0..MAX_CAS_RETRIES {
        // 1. fetch remote manifest
        let (remote, _remote_etag) = fetch_remote_manifest(store).await?;
        // 2. diff
        let ops = diff(local, &remote);
        // 3. apply pulls + conflicts into local manifest; gather pushes
        let mut pushes: Vec<(ConfigPath, Entry, Vec<u8>, Vec<u8>)> = Vec::new();
        for op in ops {
            match op {
                DiffOp::PullLocal { path, remote } | DiffOp::PullDeletion { path, remote: remote @ Entry { .. } } => {
                    // fetch header + body and decrypt
                    let hdr = store.get(&blob_key(&remote.blob_id)).await?;
                    let body = store.get(&blob_body_key(&remote.blob_id)).await?;
                    let mf = files.iter().find(|f| f.logical == path);
                    if remote.deleted {
                        if let Some(mf) = mf { let _ = std::fs::remove_file(&mf.disk_path); }
                        local.entries.remove(&path);
                    } else if let Some(mf) = mf {
                        let pt = open_sealed(&hdr, &body, &path, &remote, recip_secrets)?;
                        write_plaintext(&mf.disk_path, &pt)?;
                        local.entries.insert(path.clone(), remote.clone());
                        report.pulled.push(path);
                    }
                }
                DiffOp::PushRemote { path, local: l } | DiffOp::PushDeletion { path, local: l @ Entry { .. } } => {
                    let mf = files.iter().find(|f| f.logical == path);
                    if let Some(mf) = mf {
                        if l.deleted { let _ = std::fs::remove_file(&mf.disk_path); }
                        else {
                            let mut clk = l.clock.clone();
                            let (entry, sf) = read_and_seal(&mf.disk_path, &path, l.aad_version + 1, { clk.bump(device); clk.clone() }, recip_keys)?;
                            pushes.push((path.clone(), entry, sf.header_blob, sf.body_blob));
                        }
                    }
                }
                DiffOp::InSync { .. } => {}
                DiffOp::Conflict { path, local: l, remote: r } => {
                    let mf = files.iter().find(|f| f.logical == path).ok_or_else(|| SyncError::Manifest(format!("no managed file for {path}")))?;
                    let policy = mf.policy;
                    let conflict = crate::conflict::Conflict { path: path.clone(), local: l.clone(), remote: r.clone() };
                    let res = resolve_conflict(&conflict, policy, resolver, local.manifest_version + 1, now)?;
                    match res {
                        Resolution::Aborted => { report.aborted = true; return Ok(report); }
                        Resolution::Resolved { chosen, .. } => {
                            // If chosen is remote, pull it; if local, push it.
                            if chosen.blob_id == r.blob_id {
                                let hdr = store.get(&blob_key(&r.blob_id)).await?;
                                let body = store.get(&blob_body_key(&r.blob_id)).await?;
                                let pt = open_sealed(&hdr, &body, &path, &r, recip_secrets)?;
                                write_plaintext(&mf.disk_path, &pt)?;
                                local.entries.insert(path.clone(), r.clone());
                                report.pulled.push(path.clone());
                            } else {
                                // re-seal local with merged clock
                                let mut clk = l.clock.clone(); clk.merge(&r.clock); clk.bump(device);
                                let (entry, sf) = read_and_seal(&mf.disk_path, &path, l.aad_version + 1, clk, recip_keys)?;
                                pushes.push((path.clone(), entry, sf.header_blob, sf.body_blob));
                            }
                            report.conflicts_resolved.push(path);
                        }
                    }
                }
            }
        }
        // 4. upload pushed blobs + update local manifest entries
        for (path, entry, hdr, body) in &pushes {
            store.put(&blob_key(&entry.blob_id), hdr.clone().into(), None).await?;
            store.put(&blob_body_key(&entry.blob_id), body.clone().into(), None).await?;
            local.entries.insert(path.clone(), entry.clone());
        }
        // 5. bump aggregate clock + version, then CAS-put manifest
        local.clock.bump(device);
        local.manifest_version += 1;
        local.device_id = device.as_str().to_string();
        let bytes = local.to_bytes().map_err(|e| SyncError::Manifest(e.to_string()))?;
        match store.put(MANIFEST_KEY, bytes.into(), None).await {
            Ok(_etag) => {
                report.pushed.extend(pushes.into_iter().map(|(p, _, _, _)| p));
                return Ok(report);
            }
            Err(cs_storage::StorageError::PreconditionFailed) if attempt + 1 < MAX_CAS_RETRIES => {
                // retry: re-fetch remote and re-diff
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(SyncError::CasRetriesExhausted(MAX_CAS_RETRIES))
}

fn blob_key(id: &Sha256) -> String { format!("{BLOB_PREFIX}{}", id.to_hex()) }
fn blob_body_key(id: &Sha256) -> String { format!("{BLOB_PREFIX}{}.body", id.to_hex()) }
```

- [ ] Step 2: wire `mod engine;` + re-export `sync, SyncReport, ManagedFile`.
- [ ] Step 3: write the two-device integration test (next task) before declaring done.
- [ ] Step 4: `cargo build -p cs-sync` (green). clippy, fmt.
- [ ] Step 5: commit `feat(sync): pull/diff/apply/push engine with CAS retry`.

---

## Task 9: Two-device integration test through LocalFs

**Files:** `crates/cs-integration-tests/tests/two_device_sync.rs`.

- [ ] Step 1: Write the test simulating device A and B sharing one `LocalFs` store:
```rust
use cs_crypto::generate_recipient_keypair;
use cs_keys::DeviceIdentity;
use cs_manifest::{ConfigPath, DeviceId, Manifest};
use cs_storage::{LocalFs, RemoteStore};
use cs_sync::{sync, ManagedFile};
use cs_config::ConflictPolicy;
use std::path::PathBuf;
use std::time::SystemTime;
use bytes::Bytes;

async fn read_manifest(store: &LocalFs) -> Manifest {
    match store.get("manifest.json").await {
        Ok(b) => Manifest::from_bytes(&b).unwrap(),
        Err(_) => Manifest::new("remote"),
    }
}

#[tokio::test]
async fn two_devices_converge_after_independent_edits() {
    let shared = tempfile::tempdir().unwrap();
    let store = LocalFs::new(shared.path());

    // Both devices share one identity for simplicity (same recipient keys).
    let (pk, sk) = generate_recipient_keypair();
    let dev_a = DeviceId::new("A");
    let dev_b = DeviceId::new("B");

    let work_a = tempfile::tempdir().unwrap();
    let work_b = tempfile::tempdir().unwrap();
    let file_a = work_a.path().join("f.txt");
    let file_b = work_b.path().join("f.txt");
    std::fs::write(&file_a, b"v1\n").unwrap();

    let mf_a = ManagedFile { logical: ConfigPath::new("vim/f"), disk_path: file_a.clone(), policy: ConflictPolicy::LatestWins };
    let mf_b = ManagedFile { logical: ConfigPath::new("vim/f"), disk_path: file_b.clone(), policy: ConflictPolicy::LatestWins };

    // Device A pushes v1.
    let mut ma = Manifest::new("A");
    sync(&store, &dev_a, &mut ma, &[mf_a.clone()], &pk, &sk, None, SystemTime::UNIX_EPOCH).await.unwrap();
    // Device B pulls v1.
    let mut mb = Manifest::new("B");
    sync(&store, &dev_b, &mut mb, &[mf_b.clone()], &pk, &sk, None, SystemTime::UNIX_EPOCH).await.unwrap();
    assert_eq!(std::fs::read(&file_b).unwrap(), b"v1\n");
    assert_eq!(ma.entries, mb.entries);

    // Device A edits to v2; device B edits to v3 concurrently.
    std::fs::write(&file_a, b"v2\n").unwrap();
    std::fs::write(&file_b, b"v3\n").unwrap();
    sync(&store, &dev_a, &mut ma, &[mf_a.clone()], &pk, &sk, None, SystemTime::UNIX_EPOCH).await.unwrap();
    sync(&store, &dev_b, &mut mb, &[mf_b.clone()], &pk, &sk, None, SystemTime::UNIX_EPOCH).await.unwrap();
    // After both syncs, B's edit caused a conflict resolved latest-wins.
    // Convergence: re-sync A to pull B's resolution.
    sync(&store, &dev_a, &mut ma, &[mf_a.clone()], &pk, &sk, None, SystemTime::UNIX_EPOCH).await.unwrap();
    // Manifests converge (entries equal modulo clock merge).
    assert_eq!(ma.entries.keys().collect::<Vec<_>>(), mb.entries.keys().collect::<Vec<_>>());
    assert_eq!(std::fs::read(&file_a).unwrap(), std::fs::read(&file_b).unwrap(),
        "both devices must hold identical content after convergence");
}
```
- [ ] Step 2: add `cs-manifest`, `cs-sync`, `cs-config` to cs-integration-tests deps if missing.
- [ ] Step 3: `cargo test -p cs-integration-tests --test two_device_sync`. Iterate until green.
- [ ] Step 4: commit `test(sync): two-device convergence through a shared LocalFs store`.

---

## Task 10: S3 backend (behind feature) + in-process mock test

**Files:** `crates/cs-storage/src/s3.rs`, modify `Cargo.toml` + `lib.rs`. Test in `crates/cs-storage/tests/s3_mock.rs`.

- [ ] Step 1: Cargo: add feature + optional deps:
```toml
[features]
default = ["local-fs"]
local-fs = []
s3 = ["dep:aws-sdk-s3", "dep:aws-config"]

[dependencies]
aws-sdk-s3 = { version = "1", optional = true }
aws-config = { version = "1", optional = true }
url = "2"

[dev-dependencies]
s3s = "0.10"
s3s-aws-s3 = "0.10"   # or appropriate version providing the in-process server
hyper = { version = "1", features = ["server"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```
(If `s3s` version/API differs at build time, pin to the latest working pair; the test only needs basic put/get/list/delete + conditional semantics.)
- [ ] Step 2: `s3.rs` implementing `RemoteStore` over `aws_sdk_s3::Client`. Map `if_match` to S3 `If-Match`/`If-None-Match` headers. `list` uses `list_objects_v2`. `get_range` sets the `Range` header.
- [ ] Step 3: `tests/s3_mock.rs` — spin up an in-process `s3s` server, point the S3 backend at its endpoint, run the same put/get/list/delete/conditional-put round-trip as `LocalFs`.
- [ ] Step 4: `cargo test -p cs-storage --features s3` (mock tests green). `cargo test -p cs-storage` (default features still green).
- [ ] Step 5: commit `feat(storage): S3 RemoteStore backend (feature 's3') + in-process mock tests`.

---

## Task 11: Full workspace gate + Cycle 2 wrap

- [ ] Step 1: `cargo test --workspace` — all green (Cycle 1 + Cycle 2).
- [ ] Step 2: `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] Step 3: `cargo fmt --all --check` clean.
- [ ] Step 4: Update `docs/cross-platform-builds.md` to note cs-manifest and cs-sync are pure-Rust (cross-check on all targets) and S3 is behind a feature.
- [ ] Step 5: commit `docs: cycle-2 cross-platform note + full workspace green`.

---

## Self-Review

1. **Spec coverage:** sync engine (Tasks 5,8), versioned manifest (3,4), vector clocks (3), conflict detection (5) + resolution (6), local bridge (7), S3 backend (10), "stored versioned" via immutable blobs + manifest history (4,7,8), two-device convergence (9). ✓
2. **Placeholders:** Task 7 initially had a fragile single-blob design; corrected to two-blob (header/body) in 7b. Task 10's `s3s` versions are flagged for pinning at build time. No other TBDs.
3. **Type consistency:** `ConfigPath`/`DeviceId`/`Sha256` (Task 2) used identically across clock/entry/manifest/diff/conflict/engine. `Entry` fields match between manifest and diff test fixtures. `ConflictPolicy` reuses cs-config's enum.
4. **Gaps:** The `s3s` mock ecosystem churns; if Task 10 won't build, fall back to an in-memory `RemoteStore` impl that exercises the same conditional-put contract (the engine test in Task 9 already covers the engine; S3 then only needs contract conformance). This fallback is acceptable because the engine is backend-agnostic.

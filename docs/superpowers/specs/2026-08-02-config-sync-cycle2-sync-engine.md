# config-sync — Cycle 2: Sync Engine, S3 Backend, Conflict Resolution

**Status:** Approved (architectural choices locked in Cycle 1)
**Date:** 2026-08-02
**Cycle:** 2 of N
**Implementation:** Rust, TDD (red → green → refactor)
**Builds on:** `docs/superpowers/specs/2026-08-02-config-sync-crypto-core-design.md` (Cycle 1)

---

## 1. Purpose & Scope

Cycle 1 delivered the security foundation: hybrid PQ+classic crypto, key
management, three recovery providers, the `RemoteStore` trait with a local-fs
backend, and the TOML config schema. **Nothing actually syncs yet.**

Cycle 2 turns that foundation into a working sync tool:

1. **Sync engine** — a versioned manifest with vector clocks that detects
   changes, pushes/pulls encrypted blobs, and detects conflicts reliably
   across machines.
2. **S3 backend** — the first real cloud `RemoteStore` (AWS S3 / S3-compatible).
3. **Conflict detection & resolution** — the three policies declared in the
   config (`latest-wins`, `prompt`, `manual`) plus a resolution record so an
   interactive resolution survives a round trip.
4. **Local-file ↔ manifest bridge** — read/write managed files on disk,
   encrypt/dedup them as content-addressed blobs, and keep them in sync with
   the remote manifest.

### 1.1 Cycle 2 deliverables

- `cs-manifest` crate: versioned manifest, per-path vector clocks, history.
- `cs-sync` crate: pull → diff → apply → push with optimistic concurrency (CAS),
  conflict detection, policy-driven resolution, interactive resolver trait.
- `cs-storage` `s3` backend behind a `s3` feature.
- Local I/O: read a config set's files from disk, seal them, write them back.
- Cross-crate integration tests: two simulated devices syncing through one
  `RemoteStore` (local-fs), including a forced conflict.
- S3 backend tested against an in-process mock (no live AWS needed in CI).

### 1.2 Still deferred (later cycles)

- Proton Drive, Google Drive, iCloud, WebDAV backends (the trait makes each
  additive).
- Biometric ACL gating on keychain item creation (Cycle 1 + 2 wire the
  keychain; the platform ACL flags are a thin platform-layer concern).
- Background daemon / file watcher auto-sync.
- Native cross-platform CI runners (documented in
  `docs/cross-platform-builds.md`).

---

## 2. Design (locked from Cycle 1, refined here)

### 2.1 Remote object layout (backend-agnostic)

```
<store>/
  manifest.json               # versioned: per-path current entry + vector clock
  history/<path>/<version>    # immutable prior versions (kept for "stored versioned")
  recovery/<id>.bundle        # recovery bundles (Cycle 1)
  blobs/<sha256>              # immutable, content-addressed ciphertext
```

`manifest.json` is the **only** mutable coordination object. All other objects
are immutable and content-addressed. This makes optimistic concurrency trivial:
exactly one object (the manifest) needs a conditional put.

### 2.2 The manifest

```rust
// Type aliases to remove ambiguity:
//   DeviceId   = a short stable identifier for a device (from cs-config Identity.device_id).
//                Modeled as a newtype String wrapper for type safety.
//   ConfigPath = the logical, portable path key of a managed config entry, e.g. "vim/.vimrc".
//                Forward-slash, normalized, NOT an OS path (the cs-config PathResolver maps
//                this logical key to a real per-machine path). Newtype String wrapper.
//   Sha256     = a 32-byte content hash, hex-encoded when used as a blob id.

pub struct Manifest {
    pub schema_version: u32,          // manifest format version (independent of config schema)
    pub device_id: String,            // last writer (for diagnostics; not authoritative)
    pub clock: VectorClock,           // aggregate causal clock
    pub entries: BTreeMap<ConfigPath, Entry>,
    pub resolutions: BTreeMap<ConfigPath, ResolutionRecord>,
    pub manifest_version: u64,        // monotonic; compared by CAS
}

pub struct Entry {
    pub blob_id: Sha256,              # content-addressed ciphertext in blobs/
    pub aad_version: u64,             # bound into AEAD via the envelope
    pub clock: VectorClock,           # per-path causal clock
    pub size: u64,
    pub modified: SystemTime,
    pub deleted: bool,                # tombstone
}

pub struct ResolutionRecord {
    pub at_version: u64,              # manifest version where resolution happened
    pub chosen_blob: Sha256,
    pub superseded: Vec<Sha256>,      # the blobs merged/dropped
    pub clock: VectorClock,
}
```

**Vector clock** (Lamport-style per-device counters merged into a map):

```rust
pub struct VectorClock(pub BTreeMap<DeviceId, u64>);

impl VectorClock {
    fn happens_before(&self, other: &Self) -> bool { /* partial order */ }
    fn merge(&mut self, other: &Self);
    fn bump(&mut self, device: &DeviceId) -> u64;
    fn equal(&self, other: &Self) -> bool;
}
```

A path is **concurrent/conflicting** when neither `local.clock` nor
`remote.clock` `happens_before` the other and they differ. Identical clocks
with identical blob = no change. `happens_before` in one direction = clean
fast-forward.

### 2.3 Conflict detection algorithm

For each path in the union of local and remote manifests:

```
local_e, remote_e = entries
match (local_e, remote_e) {
    (Some(l), None)         => remote-deleted (or local-only) → policy
    (None, Some(r))         => pull (new on remote)
    (Some(l), Some(r)) if l.blob == r.blob => in sync, no-op
    (Some(l), Some(r)) if l.clock.happens_before(r.clock) => fast-forward pull
    (Some(l), Some(r)) if r.clock.happens_before(l.clock) => fast-forward push
    (Some(l), Some(r))      => CONCURRENT → conflict, policy decides
}
```

### 2.4 Conflict policies (from config)

- `LatestWins`: pick the entry with the greater `modified` time; on tie, the
  lexicographically larger blob id (deterministic). Records a
  `ResolutionRecord` so the other device converges.
- `Prompt`: invoke the interactive resolver (trait) to let the user choose
  local/remote/both/abort. Default resolver is a terminal prompt; a no-op
  resolver lets headless/CI fail loudly.
- `Manual`: never auto-resolve; surface the conflict and stop, leaving both
  versions available (e.g. `<path>.local`, `<path>.remote`) for the user to
  merge by hand.

### 2.5 Interactive resolver trait

```rust
pub enum ConflictChoice { KeepLocal, KeepRemote, KeepBoth, Abort }

pub trait ConflictResolver: Send + Sync {
    fn resolve(&self, c: &Conflict) -> Result<ConflictChoice>;
}

pub struct Conflict {
    pub path: ConfigPath,
    pub local: Option<Entry>,        // decrypted plaintext available via callback
    pub remote: Option<Entry>,
}
```

A `TerminalResolver` (using `dialoguer`) implements it; tests inject a
`FixedResolver` that returns a predetermined choice. The sync engine never
blocks on UI in non-interactive runs — `Prompt` with no resolver attached is
an error.

### 2.6 Sync operation (push and pull unified)

```
sync(store, device, local_manifest, files, resolver):
    1. remote_manifest = store.get("manifest.json") (or empty if absent)
    2. compute diff(local_manifest, remote_manifest) per path
    3. for pulls: fetch each missing blob, decrypt, write to disk
    4. for pushes: seal changed local files, put blobs, update local manifest
    5. for conflicts: apply policy / resolver, record resolutions
    6. CAS-put new manifest (if_match = remote_manifest's etag/version)
       - on PreconditionFailed: re-pull remote, re-diff, retry (bounded)
    7. return SyncReport { pulled, pushed, conflicts, errors }
```

Retries are bounded (default 3) to avoid livelock under contention.

### 2.7 S3 backend

Implements `RemoteStore` over `aws-sdk-s3`:

- `list(prefix)` → `list_objects_v2` with the prefix.
- `get` / `get_range` → `get_object` (with optional `Range` header).
- `put(name, data, if_match)` → `put_object` with the appropriate
  conditional: `If-Match` for "must equal", `If-None-Match: "*"` for "must be
  absent" (used for the manifest CAS on first write). S3 ETags are returned.
  For the manifest CAS specifically we use a monotonically-increasing key
  suffix or `If-Generation-Match`-equivalent via the manifest's own
  `manifest_version` field validated post-hoc when ETags are non-unique (S3
  multipart ETags are not content-unique). The `LocalFs`-style sidecar is not
  needed because we use the manifest's `manifest_version` + conditional put.
- `delete` → `delete_object`.
- Auth via standard AWS credential chain (env, shared config, IMDS). No
  credentials ever live in the config file.

The S3 backend is tested against `s3s` (an in-process S3 server) so CI needs
no live AWS account.

---

## 3. New crate layout

```
crates/
├── cs-manifest/         # NEW: Manifest, Entry, VectorClock, ResolutionRecord
├── cs-sync/             # NEW: diff, sync, conflict detection, resolver trait
├── cs-storage/
│   └── src/s3.rs        # NEW: S3 backend (behind feature "s3")
└── (existing crates unchanged)
```

`cs-sync` depends on `cs-manifest`, `cs-storage`, `cs-crypto`, `cs-config`,
`cs-keys`. `cs-manifest` depends only on `serde`, `postcard`, `sha2`, and
`thiserror` — it is pure data + algorithms, fully unit-testable with no I/O.

---

## 4. Testing strategy (TDD)

- **VectorClock**: property tests for partial order (happens-before is
  irreflexive, antisymmetric, transitive); merge is commutative/associative/idempotent.
- **Diff**: table-driven cases for every (local, remote) entry combination,
  including tombstones and concurrent clocks.
- **Manifest CAS**: force `PreconditionFailed` mid-sync and assert bounded retry
  + convergence.
- **Two-device simulation**: device A pushes, device B pulls, device A edits,
  both edit concurrently → conflict → resolve → both converge to identical
  manifests. Uses `LocalFs` as the shared store (no AWS needed).
- **S3 backend**: round-trip + conditional-put against an in-process `s3s`
  mock; never touches live AWS.
- **Conflict policies**: each of `LatestWins`/`Prompt`/`Manual` exercised,
  asserting the survival property (e.g. `Manual` leaves both files on disk).

Gates unchanged: `cargo test --workspace` green, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo fmt --all --check`.

---

## 5. Acceptance criteria for Cycle 2

1. Two simulated devices sharing one `RemoteStore` converge to identical
   manifests after independent edits, including a forced concurrent edit
   resolved by each policy.
2. A concurrent edit that triggers `PreconditionFailed` on manifest put
   retries and converges rather than corrupting state.
3. The S3 backend passes the same `RemoteStore` contract test suite as
   `LocalFs`, against an in-process mock (no live AWS).
4. All blobs are content-addressed and immutable; the manifest is the only
   mutable object and every mutation is CAS-protected.
5. "Stored versioned": prior versions of every path remain retrievable under
   `history/<path>/<version>` until an explicit (Cycle 3) GC.
6. Existing Cycle 1 tests remain green; no security regressions.

---

## 6. Build sequence (preview — detailed plan via writing-plans)

1. `cs-manifest`: VectorClock → Entry/Manifest → ResolutionRecord → ser/de.
2. `cs-sync`: diff → conflict detection → policies → resolver trait →
   pull/push/CAS retry loop.
3. Local-file bridge: read config set from disk, seal to blobs, write back.
4. `cs-storage` `s3` backend + `s3s` mock tests.
5. Two-device integration test through `LocalFs`.
6. Full workspace gate.

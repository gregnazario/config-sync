# config-sync — Crypto Core & Foundation Design (Cycle 1)

**Status:** Approved
**Date:** 2026-08-02
**Cycle:** 1 of N (foundation)
**Implementation:** Rust, TDD (red → green → refactor)

---

## 1. Purpose & Scope

`config-sync` synchronizes configuration files across a user's personal fleet of
machines (macOS, Windows, Linux, FreeBSD) and encrypts them end-to-end with
post-quantum-secure cryptography before they ever touch a cloud backend.

This document specifies **Cycle 1**: the security foundation. Cycle 1 delivers
the load-bearing pieces that every later subsystem depends on, so that cloud
backends, sync, and conflict resolution can be layered on top without revisiting
the cryptographic invariants.

### 1.1 Cycle 1 deliverables

1. **Crypto core** — key hierarchy, hybrid PQ+classic KEM, per-file DEK,
   AEAD envelope, self-describing versioned file format.
2. **Key management** — keychain-backed device key storage with biometric
   gating where the platform supports it.
3. **Recovery providers** — all three, pluggable:
   - Offline BIP-39 mnemonic recovery key
   - Shamir k-of-n secret sharing
   - Cloud-stored recovery bundle
4. **Storage trait + local-fs implementation** — enough to exercise the crypto
   round-trip end to end in tests and to sync via a directory / mounted volume.
5. **Config schema core** — versioned TOML schema with per-machine path maps,
   empty-field handling, and path resolution.
6. **Full TDD test coverage** for all of the above.

### 1.2 Explicitly deferred to later cycles

- Cloud backends (S3, Google Drive, iCloud, Proton Drive, WebDAV).
- Sync engine (versioned manifest, vector clocks, optimistic concurrency).
- Interactive conflict resolution UI.
- Add-device enrollment ceremony.
- Full CLI polish and background daemon.

These are *architected for* in this document so later cycles require no core
redesign, but they are not built in cycle 1.

---

## 2. Locked Decisions

| Area | Decision |
|------|----------|
| Language | Rust (edition 2021) |
| Crypto envelope | Hybrid PQ+classic: ML-KEM-768 ⊕ X25519, per-file DEK, XChaCha20-Poly1305 AEAD |
| PQ library | `pqcrypto` (liboqs bindings) |
| Trust model | Personal multi-device; cloud backends are untrusted ciphertext stores |
| Recovery | Three pluggable providers, user-selectable at init |
| Storage | `RemoteStore` trait + per-backend impls behind Cargo feature flags |
| Sync (later) | Versioned manifest + vector clocks, content-addressed blobs, optimistic concurrency |
| Config | Logical config sets with per-machine path maps; TOML, versioned |
| Surface | Verb/noun CLI (git-style); architecture is daemon-friendly |

---

## 3. Module Architecture

The system is strictly layered. A layer may depend only on layers below it, and
each layer is independently unit-testable.

```
┌─────────────────────────────────────────────────────────┐
│  CLI layer (clap)                          [cycle 2+]    │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Sync engine (manifest, vector clocks, CAS)      │ [cycle 2]
│  │  Conflict resolution UI                          │    │
│  └──────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Config layer (TOML schema, path resolution,     │ [cycle 1 core]
│  │   per-machine maps, validation)                  │    │
│  └──────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Storage layer (RemoteStore trait)               │    │
│  │   - local-fs  [cycle 1]                          │    │
│  │   - s3, gdrive, icloud, proton-drive [cycle 2+]  │    │
│  └──────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Key management (keychain, biometrics, device    │ [cycle 1]
│  │   keys, recovery providers)                      │    │
│  └──────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐    │
│  │  Crypto core (envelope, KEM, AEAD, key           │ [cycle 1 foundation]
│  │   hierarchy)                                     │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Invariant:** the crypto core has **zero** dependencies on storage, config, or
sync. It accepts plaintext bytes and returns ciphertext bytes, and vice versa.
This guarantees cloud code can never break the security invariants and that the
core is trivially property-testable.

### 3.1 Workspace layout

```
config-sync/
├── Cargo.toml                    # virtual workspace
├── crates/
│   ├── cs-crypto/                # crypto core (no I/O deps)
│   ├── cs-keys/                  # keychain, biometrics, recovery providers
│   ├── cs-storage/               # RemoteStore trait
│   │   └── backends/
│   │       └── local-fs/         # local filesystem impl (feature)
│   ├── cs-config/                # TOML schema, path resolution
│   ├── cs-sync/                  # [cycle 2] manifest, vector clocks
│   └── cs-cli/                   # [cycle 2] clap surface
├── docs/superpowers/specs/       # design docs
└── tests/                        # cross-crate integration tests
```

Each crate is a focused, independently testable unit (the design principle:
small well-bounded modules communicate through well-defined interfaces and can
be understood without reading each other's internals).

---

## 4. Crypto Core

### 4.1 Key hierarchy

```
root identity key (RIK)   32 random bytes; sealed at rest; NEVER on disk in plaintext
   │   KEK = Argon2id(...) seals RIK inside the device keychain
   ▼
master key (MK)           32 random bytes; sealed to the device root identity
   │   wraps each file's DEK
   ▼
data encryption key (DEK) per-file, 32 random bytes
                          encrypts plaintext via XChaCha20-Poly1305
```

- **RIK** is the user's long-term identity. It is the only secret that must
  survive device loss, hence the recovery providers seal *it*.
- **MK** is per-device/per-vault. Rotating it re-wraps DEKs, not plaintexts.
- **DEK** is unique per file, so no key reuse across content and rotation is
  cheap. A compromised DEK affects exactly one file.

### 4.2 Hybrid KEM (PQ + classic)

Defends against both "harvest now, decrypt later" PQ attacks and against a
future break in *either* primitive.

**Seal (encryption side):**
1. Load `(pk_pq, sk_pq)` ML-KEM-768 and `(pk_x, sk_x)` X25519 for the recipient
   (in cycle 1 the recipient is the same device's identity; cycle 2 introduces
   per-device pubkeys).
2. `(ss_pq, ct_pq) = ML-KEM-768::encaps(pk_pq)`.
3. ephemeral `e = X25519::gen()`, `ss_classic = X25519(e, pk_x)`, `ct_classic = e`.
4. `wrap_key = HKDF-SHA256(ss_pq ‖ ss_classic, info="csync/hybrid-v1")`.

**Open (decryption side):**
1. `ss_pq = ML-KEM-768::decaps(sk_pq, ct_pq)`.
2. `ss_classic = X25519(sk_x, ct_classic)`.
3. `wrap_key = HKDF-SHA256(ss_pq ‖ ss_classic, info="csync/hybrid-v1")`.

If either private key is unknown, `wrap_key` is unrecoverable. Concatenation +
HKDF is the standard, conservative combiner (matches HPKE / age-PQC guidance).

### 4.3 File envelope (self-describing, versioned)

```
header:
  magic        b"CSYNC1"   (6 bytes)
  version      u8          (1 byte; currently 1)
  kem_pq_ct                ML-KEM-768 ciphertext (1088 bytes)
  kem_classic_ct           X25519 ephemeral pubkey (32 bytes)
  wrapped_dek              AEAD(wrap_key, nonce_dek, DEK, aad=header_aad)
  aad                      path + version, bound into all AEAD calls
body:
  nonce         (24 bytes)
  ciphertext+tag           XChaCha20-Poly1305(DEK, nonce, plaintext, aad)
```

- The magic + version prefix makes the format self-identifying and allows
  future in-place format evolution (`CSYNC2`, …) without ambiguity.
- **AAD** binds the path and version into every AEAD operation so a ciphertext
  cannot be relocated or replayed against a different file/version.
- XChaCha20-Poly1305 with 24-byte nonces permits random nonces safely
  (nonce-misuse resistance in practice for the volumes here).

### 4.4 Primitive justification

| Primitive | Role | Why |
|-----------|------|-----|
| ML-KEM-768 | PQ KEM | FIPS 203, NIST-selected, Cat-1 PQ security |
| X25519 | Classic KEM | Universally audited, conservative |
| XChaCha20-Poly1305 | AEAD | 24-byte nonce → random nonces safe; fast, constant-time |
| Argon2id | Recovery KEK | Memory-hard, resists GPU/ASIC brute force |
| HKDF-SHA256 | KEM combiner / key derivation | Standard, conservative |

### 4.5 Public API (crate `cs-crypto`)

```rust
pub struct Envelope;        // stateless facade

pub struct SealOutput { pub header: Vec<u8>, pub body: Vec<u8> }
pub struct OpenInput <'a> { pub header: &'a [u8], pub body: &'a [u8] }

impl Envelope {
    pub fn seal(plaintext: &[u8], aad: &Aad, recipient: &RecipientKeys)
        -> Result<SealOutput>;
    pub fn open(input: OpenInput, aad: &Aad, recipient: &RecipientSecrets)
        -> Result<Vec<u8>>;
}

pub struct Aad { pub path: String, pub version: u64 }   // bound into AEAD
pub struct RecipientKeys   { pub kem_pq: PublicKey,  pub kem_classic: PublicKey }
pub struct RecipientSecrets{ pub kem_pq: SecretKey,   pub kem_classic: SecretKey }

// Key generation / wrapping (the hierarchy in §4.1)
pub fn generate_rik() -> [u8; 32];
pub fn generate_mk() -> [u8; 32];
pub fn generate_dek() -> [u8; 32];
pub fn wrap_key(key: &[u8;32], kek: &[u8;32], aad: &Aad) -> Result<WrappedKey>;
pub fn unwrap_key(wrapped: &WrappedKey, kek: &[u8;32], aad: &Aad) -> Result<[u8;32]>;
```

The API is synchronous and allocation-based; performance is not a concern at
config-file sizes. Backends handle async; the core does not.

---

## 5. Key Management & Recovery

### 5.1 At-rest device storage

- The `keyring` crate abstracts platform backends:
  - **macOS** → Keychain
  - **Windows** → Credential Manager
  - **Linux / FreeBSD** → Secret Service (GNOME Keyring / KWallet)
- The RIK is stored sealed in the keychain under a stable service/account name.
- The MK lives only in process memory during a sync operation and is dropped on
  lock/quit.

### 5.2 Biometric gating

- **macOS:** keychain item is created with an access control flag requiring
  Touch ID / device passcode to release (ACL `biometryAny`/`or` device passcode).
- **Windows:** stored via CNG with NGC (Next Generation Credential) where
  available so Windows Hello (face/fingerprint/PIN) gates release.
- **Linux / FreeBSD:** no standard biometric keychain API, so we fall back to
  Secret Service plus an optional local passphrase unlock. Biometrics here is a
  best-effort convenience, not a guarantee.

### 5.3 Secret store abstraction (for testability)

```rust
pub trait SecretStore: Send + Sync {
    fn put(&self, account: &str, secret: &[u8]) -> Result<()>;
    fn get(&self, account: &str) -> Result<Vec<u8>>;
    fn delete(&self, account: &str) -> Result<()>;
}
```

- `KeyringStore` wraps the `keyring` crate for production.
- `InMemoryStore` is a pure-Rust impl used for CI and unit tests so keychain
  tests never touch the host OS keychain in CI.
- Biometric gating is a property of `KeyringStore`; tests for it run only on
  developer machines behind a feature flag.

### 5.4 Recovery provider trait

```rust
pub trait RecoveryProvider {
    fn seal(&self, rik: &[u8; 32]) -> Result<RecoveryBundle>;
    fn recover(&self, bundle: &RecoveryBundle) -> Result<[u8; 32]>;
    fn kind(&self) -> RecoveryKind;
}

pub enum RecoveryKind { Mnemonic, Shamir { k: u8, n: u8 }, CloudBundle }
```

All three providers seal the **same RIK**, so a user may enable more than one
for defense in depth.

#### 5.4.1 Offline mnemonic

1. `recovery_key = random(256 bits)`.
2. Render as a 24-word BIP-39 mnemonic (`bip39` crate) for human transcription.
3. `KEK = Argon2id(recovery_key, salt, m=64 MiB, t=3, p=4)`.
4. `sealed_rik = AEAD(KEK, RIK)`; bundle stores `{salt, sealed_rik}`.
5. Recover: user types the words → derive KEK → decrypt. No cloud, no network.

#### 5.4.2 Shamir k-of-n

1. Split RIK into `n` shares, threshold `k`, via the `sharks` crate. Default
   is `k=2, n=3` (survives loss of one share, requires two to recover).
2. Default distribution of shares (configurable): mnemonic (one share), a
   trusted contact's ML-KEM-768 pubkey (one share, sealed to it), a local
   device file (one share).
3. Recover by collecting any `k` shares and recombining.

#### 5.4.3 Cloud-stored bundle

1. `KEK = Argon2id(passphrase, salt)` with the same strong parameters.
2. `bundle = AEAD(KEK, RIK)`.
3. Bundle is pushed to a configured `RemoteStore` under `recovery/<id>.bundle`.
4. Recover from any device that can reach the store and supply the passphrase.

> The recovery ciphertext lives on the same cloud providers used for sync, but
> it is ciphertext only; the provider cannot decrypt it. The user's passphrase
> strength is the binding constraint, hence Argon2id with heavy parameters.

### 5.5 Add-device ceremony (defined now, built in cycle 2)

A new device generates its own RIK and ML-KEM/X25519 pubkeys, displays them,
and an existing device — after biometric unlock — seals a one-time enrollment
token to the new device's pubkeys. The new device imports the token. This lets
RIK-protected data be shared across devices without ever reusing a single
device's identity.

---

## 6. Storage Layer

### 6.1 `RemoteStore` trait

```rust
#[async_trait]
pub trait RemoteStore: Send + Sync {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>>;
    async fn get(&self, name: &str) -> Result<Bytes>;
    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes>;
    async fn put(&self, name: &str, data: Bytes, if_match: Option<Etag>) -> Result<Etag>;
    async fn delete(&self, name: &str) -> Result<()>;
    fn capabilities(&self) -> Capabilities;
}

pub struct ObjectMeta { pub name: String, pub etag: Etag, pub size: u64, pub mtime: SystemTime }
pub struct Capabilities { pub range_get: bool, pub conditional_put: bool }
```

- `if_match` implements optimistic concurrency / store-level conflict
  detection. Backends with native ETags (S3) map directly; backends without
  (local FS) emulate via a `.version` sidecar or inode mtime compare.
- `capabilities()` lets the sync engine (cycle 2) adapt to backend limits
  rather than guessing.

### 6.2 Remote object layout (backend-agnostic)

```
<store>/
  manifest.json          versioned: per-path current version + vector clock  [cycle 2]
  recovery/
    <id>.bundle          recovery bundles
  blobs/
    <sha256>             immutable, content-addressed ciphertext
```

### 6.3 Cycle 1 backend: `local-fs`

- Syncs to a directory (mounted drive, Syncthing folder, etc.).
- Conditional put emulated with a `.version` sidecar storing an ETag counter.
- Fully exercises the crypto round-trip in integration tests.

### 6.4 Later-cycle backends (architected for, not built now)

`local-fs` (this cycle), then `s3` (aws-sdk-s3), `gdrive` (REST + OAuth),
`icloud` (FS on macOS / WebDAV elsewhere), `proton-drive`, `webdav`. Each lives
behind a Cargo feature so unused backends add no build weight.

---

## 7. Config Schema (TOML, versioned, future-proof)

### 7.1 Goals baked into the schema

- **Versioned** via `schema_version`; unknown keys are tolerated with a warning
  so older clients do not choke on newer configs.
- **Empty fields are first-class** — empty `host`/`platform` string means
  "matches any"; empty `fields.*` is preserved, not dropped.
- **One logical config, many per-machine paths** via `[[config.location]]`
  arrays matched by `host` and/or `platform`.
- **Easy path handling** — a `PathResolver` expands `~`, `$VAR` (Unix) and
  `%VAR%` (Windows), normalized per platform. Pure function, fully unit-tested.
- **Per-set conflict policy** drives the cycle-2 interactive resolver.
- **Multiple destinations for the same configs** — `primary` plus `secondary`
  backend names push the same blobs to several stores.

### 7.2 Example

```toml
schema_version = 1

[identity]
device_id = "a1b2..."              # stable id of this device

[[config]]
name = "vim"
conflict_policy = "prompt"         # latest-wins | prompt | manual
ignore = ["*.swp", "*.tmp"]

  [[config.location]]
  host = "macbook-pro"
  platform = ""                    # empty = any
  path = "~/.vimrc"

  [[config.location]]
  host = ""
  platform = "windows"
  path = "%APPDATA%/vim/_vimrc"

  [[config.location]]
  host = ""
  platform = "linux"
  path = "~/.config/nvim/init.vim"

  [config.fields]
  theme = ""
  editor = ""

[storage]
primary = "local-repo"
secondary = ["s3-backup"]

  [[storage.backend]]
  name = "local-repo"
  kind = "local-fs"
  path = "~/Sync/config-sync"

  [[storage.backend]]
  name = "s3-backup"
  kind = "s3"
  bucket = "my-config-sync"
  region = "us-east-1"
  prefix = "config-sync/"
```

### 7.3 Path resolution rules

| Input | macOS / Linux / FreeBSD | Windows |
|-------|-------------------------|---------|
| `~` | `$HOME` | `%USERPROFILE%` |
| `$HOME`/`$VAR` | expanded | left as-is (use `%VAR%`) |
| `%APPDATA%`/`%VAR%` | left as-is | expanded |
| relative path | rejected at validation | rejected at validation |

Resolution is a pure `PathResolver::resolve(raw, platform) -> PathBuf` and is
unit-tested across all platforms without touching the real filesystem.

---

## 8. Testing Strategy (TDD)

The project is built test-first: red → green → refactor for every unit.

- **Property tests** (`proptest`) for envelope round-trips: random plaintext
  across sizes 0..1 MiB, many keypairs — `open(seal(x)) == x` always; any
  tampered byte fails AEAD.
- **Known-answer tests (KAT)** for ML-KEM-768 from NIST FIPS 203 vectors to
  confirm the liboqs binding behaves correctly.
- **Deterministic vectors** committed for the hybrid KEM recombination so a
  regression is obvious in review.
- **Integration round-trip** (local-fs): encrypt → store → retrieve → decrypt
  equals original.
- **Keychain tests** run only on developer machines behind a feature flag; CI
  uses `InMemoryStore` for determinism.
- Gates at every commit: `cargo test` green, `cargo clippy -- -D warnings`,
  `cargo fmt --check`.

---

## 9. Security Properties (acceptance criteria for cycle 1)

1. A file encrypted on one device can only be decrypted by a holder of the RIK
   (or a configured recovery provider that seals the RIK).
2. Tampering with any byte of header or body causes `open` to fail.
3. The AAD (path + version) is authenticated: relocating a ciphertext to a
   different path/version fails decryption.
4. The cloud store and recovery bundles contain only ciphertext; compromise of
   any backend reveals no plaintext.
5. Loss of all devices is recoverable via any single enabled recovery provider
   (mnemonic words / k Shamir shares / passphrase + store access).
6. On macOS and Windows, releasing the RIK from the keychain is gated by
   biometrics where configured; on Linux/FreeBSD the documented fallback applies.

---

## 10. Build Sequence (preview — detailed plan produced by writing-plans)

1. Scaffold Rust workspace + crate skeletons + CI lint/format gates.
2. cs-crypto: primitives, hybrid KEM, envelope — all TDD.
3. cs-keys: SecretStore trait + InMemory/Keyring impls.
4. cs-keys: three recovery providers.
5. cs-storage: RemoteStore trait + local-fs backend.
6. cs-config: TOML schema + path resolver.
7. Integration tests across crates.

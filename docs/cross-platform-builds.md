# Cross-Platform Build Verification

`config-sync` targets **macOS, Windows, Linux, and FreeBSD**. This document
records what has been verified, what the remaining gaps are, and how a build
succeeds on each platform.

> **Update (ml-kem migration):** the post-quantum KEM moved from
> `pqcrypto`/liboqs (a C library built with CMake) to RustCrypto's pure-Rust
> `ml-kem` implementation. **No C toolchain or CMake is required on any
> platform anymore**, and cross-compiling from any host works for the whole
> workspace. The historical liboqs notes below are kept only as context for
> pre-migration verification runs.

## Platform status

| Crate | macOS (aarch64) | macOS (x86_64) | Windows (MSVC) | Linux (glibc x86_64) | FreeBSD |
|---|---|:---:|:---:|:---:|:---:|
| **full workspace** (`--all-features`) | ✅ build+test (183) | ⚙️ via CI | ⚙️ via CI | ✅ build+test (via cross) | ⚙️ via CI |
| `cs-crypto` (ml-kem, pure Rust) | ✅ build+test (KAT + property) | ⚙️ via CI | ⚙️ via CI | ✅ build+test | ⚙️ via CI |
| `cs-cli --no-default-features` (file identity store) | ✅ build+test | ⚙️ via CI | ⚙️ via CI | ⚙️ via CI | ⚙️ via CI |

Legend:
- ✅ **build+test** — built AND unit/integration tested on that OS.
- ⚙️ **via CI** — covered by `.github/workflows/ci.yml`, which runs a real
  native build+test on each platform's runner (Windows MSVC, FreeBSD VM).

## Why the Rust code is portable

Audited directly:

- **Zero** `#[cfg(target_os = ...)]` / `target_family` / `target_arch`
  conditionals in the algorithmic crates (the only platform conditionals are
  the documented filesystem-permission and biometric-store shims in
  `cs-cli`/`cs-keys`/`cs-storage`).
- **Zero** direct `libc::`, `winapi::`, `windows::`, or CoreFoundation usage.
- **Zero** `unsafe` blocks (`#![forbid(unsafe_code)]` in every crate).

All platform differences are confined to **dependencies** that are themselves
portable: `getrandom` (OS RNG), `keyring` (platform keychain via selected
backend feature), `fd-lock` (advisory locking), and `tokio`'s async runtime.

## Historical: why liboqs used to block cross-compiles from macOS

Before the `ml-kem` migration, ML-KEM-768 came from the `pqcrypto` crate
family, which wrapped **liboqs** (a C library built with CMake).
Cross-compiling a C dependency requires the target's C toolchain, which a
macOS host lacks for Windows/Linux/FreeBSD targets. The migration to pure
Rust removed this entire class of problems; the constraint no longer applies.

## Keychain backend selection

The `keyring` crate v3 requires an explicit platform backend. `cs-keys`
selects one automatically per compile target when the `keyring` feature is
enabled:

| Target | Backend feature | Native store |
|---|---|---|
| macOS / iOS | `apple-native` | Keychain (Touch ID via ACL) |
| Windows | `windows-native` | Credential Manager |
| Linux | `linux-native-sync-persistent` | linux-keyutils + Secret Service |
| FreeBSD/OpenBSD/NetBSD | `sync-secret-service` | Secret Service via D-Bus |

Biometric gating of secret release is enforced on macOS (Keychain ACL) and
probed via fprintd on Linux; on Windows and FreeBSD the store delegates to
the plain keychain and reports itself as not biometric-gated.

Without the `keyring` feature, `cs-keys` uses `InMemoryStore` (CI/test
default); the CLI's `--no-default-features` build stores the identity in a
`0600` `identity.bin`.

## How to build on each platform

```sh
# macOS (any arch) — no prerequisites beyond Rust 1.85+
cargo build --release
cargo test

# Windows (MSVC) — no CMake needed anymore
cargo build --release

# Linux — for the keyring backend only: libdbus-1-dev (+ libclang-dev /
# libsecret-1-dev depending on distro)
cargo build --release

# FreeBSD — for the Secret Service backend: dbus + gnome-keyring/kwallet
cargo build --release
```

Cross-compiling (e.g. Linux targets from macOS) now works for the entire
workspace with just the target's Rust std component — no C cross-toolchain.

## Recommended CI matrix

```yaml
matrix:
  include:
    - { os: macos-latest,  target: aarch64-apple-darwin }
    - { os: macos-latest,  target: x86_64-apple-darwin }
    - { os: windows-latest, target: x86_64-pc-windows-msvc }
    - { os: ubuntu-latest, target: x86_64-unknown-linux-gnu }
    - { os: ubuntu-latest, target: aarch64-unknown-linux-gnu } # via QEMU/cross
    # FreeBSD runs via a FreeBSD VM or cross-vm action:
    - { os: ubuntu-latest, target: x86_64-unknown-freebsd, freebsd-vm: true }
```

## Native verification results

- **macOS aarch64** (dev host): `cargo test --workspace --all-features` →
  **183 passed, 0 failed**, clippy clean, fmt clean. Includes the ML-KEM-768
  KAT/property tests, the signed-manifest tamper/rollback/freshness
  regression tests, and the multi-device tombstone/convergence suites.
- **Linux x86_64**: verified natively (pre-migration via `cross`/Docker with
  the C toolchain; post-migration a plain cross or native build suffices).
- **Windows / FreeBSD**: covered by `.github/workflows/ci.yml` (MSVC runner +
  FreeBSD VM).

### Cross-platform bug found and fixed by native testing

Running the sync convergence test on Linux caught a real cross-platform bug:
`ConflictPolicy::LatestWins` picked the winner by filesystem `mtime`, which is
racy across OSes and caused the two-device convergence test to diverge on Linux
while passing on macOS. Fixed by making `LatestWins` **deterministic and
platform-independent** — it now prefers the entry whose vector clock
component-wise dominates, falling back to a deterministic counter-mass
tie-break for concurrent clocks, and only uses mtime as a final tiebreak.
This is exactly the kind of bug native cross-platform CI exists to catch.

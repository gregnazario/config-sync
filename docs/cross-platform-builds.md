# Cross-Platform Build Verification

`config-sync` targets **macOS, Windows, Linux, and FreeBSD**. This document
records what has been verified, what the remaining gaps are, and how a build
succeeds on each platform.

## Platform status

| Crate | macOS (aarch64) | macOS (x86_64) | Windows (MSVC) | Linux (glibc x86_64) | FreeBSD |
|---|:---:|:---:|:---:|:---:|:---:|
| **full workspace** (`--features cs-storage/local-fs`) | ✅ build+test (128) | ✅ via CI | ⚙️ via CI | ✅ **build+test (129, native via cross)** | ⚙️ via CI |
| `cs-crypto` (liboqs/ML-KEM) | ✅ build+test | ✅ via CI | ⚙️ via CI | ✅ **native build+test (KAT + property)** | ⚙️ via CI |
| `cs-keys` (liboqs) | ✅ build+test | ✅ via CI | ⚙️ via CI | ✅ **native build+test** | ⚙️ via CI |

Legend:
- ✅ **build+test** — natively built AND unit/integration tested on that OS.
  macOS (aarch64) is the dev host; **Linux x86_64 is verified natively via
  `cross` (Docker, real gcc/cmake/liboqs build)** — 129 tests passing, exit 0,
  including the liboqs-dependent ML-KEM-768 KAT and crypto property tests.
- ⚙️ **via CI** — covered by `.github/workflows/ci.yml`, which runs a real
  native build+test on each platform's runner (Windows MSVC, FreeBSD VM).
  The workflow is committed; it runs on push/PR.

> **Cycle 2 additions:** `cs-manifest` is pure Rust (serde/postcard/sha2) and
> type-checks on all four platforms. `cs-sync`'s logic is pure Rust; its only
> non-Rust transitive dependency is the same `pqcrypto`/liboqs pulled through
> `cs-crypto`, so its cross-build status mirrors `cs-crypto`. The `s3` backend
> (aws-sdk-s3) is an additive Cargo feature; without it the AWS SDK is not
> compiled into the binary at all.

Legend:
- ✅ **host** — built and unit-tested on the host platform.
- ✅ **check** — `cargo check --target <triple>` type-checks cleanly from a
  macOS host.
- ⛔ **liboqs** — the crate's own Rust code is fine; compilation halts because
  `pqcrypto-internals` needs the **target platform's C compiler** to build
  liboqs (a C library). This is a cross-compile toolchain limitation, **not** a
  code defect.

## Why liboqs blocks cross-compiles from macOS

The post-quantum KEM (`ML-KEM-768`) is provided by the `pqcrypto` crate family,
which wraps **liboqs** (a C library built with CMake). Cross-compiling a C
dependency requires the target's C toolchain:

- Windows → needs MSVC or `x86_64-w64-mingw32-gcc`
- Linux   → needs `x86_64-linux-gnu-gcc`
- FreeBSD → needs a FreeBSD-targeting `cc`

A macOS host has none of these, so `cargo check --target` stops at the C build.
**On the actual target machine** (or in CI with the right image), liboqs builds
natively — CMake + the platform compiler handle it on Windows, Linux, and
FreeBSD.

## Why the Rust code is portable

Audited directly:

- **Zero** `#[cfg(target_os = ...)]` / `target_family` / `target_arch`
  conditionals in our own crates.
- **Zero** direct `libc::`, `winapi::`, `windows::`, or CoreFoundation usage.
- **Zero** `unsafe` blocks (`#![forbid(unsafe_code)]` in every crate).

All platform differences are confined to **dependencies** that are themselves
portable: `getrandom` (OS RNG), `keyring` (platform keychain via selected
backend feature), and `tokio`'s async runtime. The `pqcrypto` C dependency is
the single non-Rust component.

## Keychain backend selection

The `keyring` crate v3 requires an explicit platform backend. `cs-keys`
selects one automatically per compile target when the `keyring` feature is
enabled:

| Target | Backend feature | Native store |
|---|---|---|
| macOS / iOS | `apple-native` | Keychain (Touch ID via ACL) |
| Windows | `windows-native` | Credential Manager / NGC (Windows Hello) |
| Linux | `linux-native-sync-persistent` | linux-keyutils + Secret Service |
| FreeBSD/OpenBSD/NetBSD | `sync-secret-service` | Secret Service via D-Bus |

Without the `keyring` feature, `cs-keys` uses `InMemoryStore` (CI/test default)
and no platform keychain is touched.

## How to build on each platform

### macOS (any arch)
```sh
cargo build --release
cargo test
```

### Windows
Requires Visual Studio Build Tools (MSVC) and CMake.
```powershell
cargo build --release --features cs-keys/keyring
```

### Linux
Requires `gcc`, `cmake`, and (for the keyring backend) `libdbus-1-dev` plus
`libclang-dev`/`libsecret-1-dev` depending on distro.
```sh
cargo build --release --features cs-keys/keyring
```

### FreeBSD
Requires `gcc`/`clang`, `cmake`, `dbus`, and `gnome-keyring` or `kwallet` for
the Secret Service backend.
```sh
cargo build --release --features cs-keys/keyring
```

## Recommended CI matrix

The following targets should be built in CI on their native images. The pure
Rust crates (`cs-config`, `cs-storage`) cross-check from any host; the
liboqs-dependent crates require a native runner.

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

Each native job runs `cargo test`; cross-arch Linux jobs run `cargo check`.

## Native verification results

- **macOS aarch64** (dev host): `cargo test --workspace` → **128 passed, 0 failed**.
- **Linux x86_64** (native via `cross` / Docker, real gcc + CMake + liboqs build):
  `cross test --workspace --target x86_64-unknown-linux-gnu --no-default-features --features cs-storage/local-fs`
  → **129 passed, 0 failed, exit 0**. Includes the liboqs-dependent
  `cs-crypto` (ML-KEM-768 KAT, hybrid KEM, envelope property tests) and
  `cs-keys` (recovery providers), proving the post-quantum crypto works
  natively on Linux.
- **Windows / FreeBSD**: covered by `.github/workflows/ci.yml` (MSVC runner +
  FreeBSD VM). The workflow installs each platform's native C toolchain
  (MSVC + CMake on Windows; `pkg install rust cmake` on FreeBSD) so liboqs
  builds there too.

### Cross-platform bug found and fixed by native testing

Running the sync convergence test on Linux caught a real cross-platform bug:
`ConflictPolicy::LatestWins` picked the winner by filesystem `mtime`, which is
racy across OSes and caused the two-device convergence test to diverge on Linux
while passing on macOS. Fixed by making `LatestWins` **deterministic and
platform-independent** — it now prefers the entry whose vector clock
component-wise dominates, falling back to a deterministic counter-mass
tie-break for concurrent clocks, and only uses mtime as a final tiebreak.
This is exactly the kind of bug native cross-platform CI exists to catch.

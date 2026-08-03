# Cross-Platform Build Verification

`config-sync` targets **macOS, Windows, Linux, and FreeBSD**. This document
records what has been verified, what the remaining gaps are, and how a build
succeeds on each platform.

## Platform status (Cycle 1)

| Crate | macOS (aarch64) | Windows (MSVC) | Linux (glibc) | FreeBSD |
|---|:---:|:---:|:---:|:---:|
| `cs-config` | ✅ host | ✅ check | ✅ check | ✅ check |
| `cs-storage` (default features) | ✅ host | ✅ check | ✅ check | ✅ check |
| `cs-manifest` (pure Rust, no C deps) | ✅ host | ✅ check | ✅ check | ✅ check |
| `cs-sync` (depends on cs-crypto via cs-storage only at type level; pure-Rust logic) | ✅ host | (see cs-crypto) | (see cs-crypto) | (see cs-crypto) |
| `cs-ui` (default = terminal feature; dialoguer/console) | ✅ host | (native build) | (native build) | (native build) |
| `cs-ui` (`--no-default-features`) — logic is pure Rust but pulls cs-sync→cs-crypto | ✅ host | (see cs-crypto) | (see cs-crypto) | (see cs-crypto) |
| `cs-keys` (default features) | ✅ host | ⛔ liboqs | ⛔ liboqs | ⛔ liboqs |
| `cs-keys` (`--features keyring`) | ✅ apple-native | (native build) | (native build) | (native build) |
| `cs-crypto` | ✅ host + tests | ⛔ liboqs | ⛔ liboqs | ⛔ liboqs |
| `cs-storage` (`--features s3`) | (native build) | (native build) | (native build) | (native build) |
| `cs-storage` (`--features webdav`) reqwest+rustls | (native build) | (native build) | (native build) | (native build) |
| `cs-storage` (`--features gdrive`) reqwest+rustls+serde | (native build) | (native build) | (native build) | (native build) |

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

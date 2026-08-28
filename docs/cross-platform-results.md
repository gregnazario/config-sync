# Cross-Platform Native Verification Results

> **Historical record:** these runs predate the `ml-kem` migration (the KEM
> was then provided by `pqcrypto`/liboqs, a C dependency). The workspace is
> now pure Rust — no liboqs, CMake, or C compiler is involved on any platform
> — but the verification evidence below remains accurate as a snapshot of
> that era. Current counts: 183 tests (`--workspace --all-features`) on the
> dev host.

The objective requires config-sync to work on **Mac, Windows, most Linux,
FreeBSD**. This document records the real native build+test evidence for each.

## CI

GitHub Actions workflow: `.github/workflows/ci.yml`. Repository:
`gregnazario/config-sync` (private). The workflow runs a real native build+test
on every platform's runner — including the liboqs-dependent `cs-crypto` and
`cs-keys` crates (liboqs is C, compiled natively per platform via CMake + the
platform's gcc/clang/MSVC).

## Verified native results

| Platform | Runner | liboqs compiled? | Tests | Status |
|---|---|:---:|:---:|:---:|
| **macOS aarch64** | `macos-14` | ✅ (CMake/clang) | ✅ build+test+clippy+fmt | ✓ green |
| **Linux x86_64** | `ubuntu-22.04` | ✅ (CMake/gcc) | ✅ build+test+clippy+fmt | ✓ green |
| **Windows x86_64 (MSVC)** | `windows-2022` | ✅ (CMake/MSVC) | ✅ build+test | ✓ green |
| **FreeBSD x86_64** | `ubuntu-22.04` + FreeBSD VM | ✅ (CMake/gcc) | ✅ build+test | ✓ green |
| **macOS x86_64** | `macos-13` | ✅ (CMake/clang) | ✅ | ✓ green |

All four named target operating systems build and test green natively. The
liboqs post-quantum crypto (ML-KEM-768) compiles and passes its KAT + property
tests on every platform.

### Local (non-CI) verification

- **macOS aarch64** (dev host): `cargo test --workspace` → 128 passed, 0 failed.
- **Linux x86_64** (native via `cross` / Docker, real gcc + CMake + liboqs):
  `cross test --workspace --target x86_64-unknown-linux-gnu` → 129 passed,
  0 failed, exit 0. Includes `mlkem768_decap_recovers_shared_secret`,
  `envelope_round_trip_arbitrary`, and all recovery-provider tests.

## Cross-platform bugs found and fixed by native testing

Native cross-platform CI caught **three** real bugs that macOS-only testing
missed:

1. **`ConflictPolicy::LatestWins` divergence on Linux.** The winner was chosen
   by filesystem `mtime`, which is racy across OSes — the two-device
   convergence test passed on macOS but failed on Linux because mtimes ordered
   differently. Fixed by making `LatestWins` deterministic and
   platform-independent: component-wise vector-clock comparison with a
   deterministic counter-mass tie-break for concurrent clocks.

2. **`security-framework` compiled on Windows.** The biometric feature's
   `security-framework` dependency was declared platform-agnostically, so
   Windows tried to compile `core-foundation` (which needs `os::unix`) and
   failed. Fixed by gating the dependency to `cfg(target_os = "macos")`.

3. **`LocalFs::list` returned backslash paths on Windows.** On Windows,
   `Path::strip_prefix` + `to_string_lossy` produced `blobs\abc` (OS separator),
   but logical config paths are forward-slash everywhere, so `list` tests
   failed. Fixed by normalizing the returned name to forward slashes.

This is exactly the value of native cross-platform CI: each bug was invisible
on macOS and would have shipped broken on the target platform.

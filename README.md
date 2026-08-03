# config-sync

Sync your config files across machines with **post-quantum end-to-end encryption**.

config-sync encrypts your dotfiles and configs with hybrid ML-KEM-768 + X25519
key encapsulation and XChaCha20-Poly1305 AEAD, then syncs the ciphertext to your
choice of cloud storage (S3, Google Drive, OneDrive, Proton Drive, iCloud via
WebDAV, or a local folder). Your cloud provider never sees plaintext.

## Features

- **Post-quantum E2E encryption** — hybrid ML-KEM-768 (NIST FIPS 203) + X25519,
  per-file DEK, XChaCha20-Poly1305 AEAD. Harvest-now-decrypt-later safe.
- **6 cloud backends** — S3, Google Drive, OneDrive, WebDAV (iCloud /
  Nextcloud / ownCloud / Synology / box.com), Proton Drive (folder + gateway),
  plus local filesystem.
- **Versioned sync** — content-addressed blobs + a versioned manifest with
  vector clocks and optimistic concurrency (CAS).
- **Interactive conflict resolution** — latest-wins / prompt / manual policies,
  with a terminal resolver (dialoguer).
- **Key recovery** — BIP-39 mnemonic, Shamir k-of-n, or passphrase-protected
  cloud bundle.
- **Biometrics** — Touch ID/Face ID (macOS), Windows Hello (Windows),
  fprintd fingerprint (Linux). Disable with `--no-biometrics`.
- **Cross-platform** — macOS, Windows, Linux, FreeBSD. Native CI verified on all four.

## Install

### One-liner (any platform with Rust)

```sh
cargo binstall config-sync
```

### Package managers

| Platform | Method | Command |
|---|---|---|
| Any (Rust toolchain) | cargo-binstall | `cargo binstall config-sync` |
| macOS / Linux | Homebrew | `brew tap gregnazario/config-sync && brew install config-sync` |
| Debian / Ubuntu | apt (.deb) | `sudo dpkg -i config-sync_*_amd64.deb` |
| Fedora / RHEL | dnf (.rpm) | `sudo dnf install config-sync-*.x86_64.rpm` |
| Alpine | apk | `apk add --allow-untrusted config-sync-*.apk` |
| Void Linux | xbps | `xbps-install config-sync` |
| Arch Linux | AUR | `yay -S config-sync-bin` |
| Any (mise) | mise | `mise use -g ubi:gregnazario/config-sync` |
| Windows | Chocolatey | `choco install config-sync` |
| Windows | WinGet | `winget install gregnazario.config-sync` |
| Windows | Scoop | `scoop install config-sync` |
| NixOS | Nix | `nix run github:gregnazario/config-sync` |

### Build from source

```sh
# Requires: Rust 1.75+, CMake, a C compiler (gcc/clang/MSVC)
cargo build --release
# Binary: target/release/config-sync

# Optional cloud backends:
cargo build --release --features cs-storage/webdav,cs-storage/gdrive,cs-storage/onedrive
```

## Quick start

```sh
# Initialize on each machine (generates device identity + config)
config-sync init

# Register a config file to manage
config-sync add vim ~/.vimrc --policy latest-wins

# Sync to the remote store (push + pull)
config-sync sync

# Diagnose the setup
config-sync doctor
```

See `docs/usage.md` for the full guide, and `docs/cloud-sync-folders.md` for
configuring Proton Drive / iCloud / Dropbox folder sync.

## Architecture

```
config-sync
├── cs-crypto      Hybrid PQ+classic KEM, per-file DEK, AEAD envelope
├── cs-keys        Keychain + biometrics, device identity, recovery providers
├── cs-storage     RemoteStore trait: S3, Google Drive, OneDrive, WebDAV,
│                  Proton Drive, local-fs, in-memory
├── cs-config      Versioned TOML config with per-machine path maps
├── cs-manifest    Versioned manifest, vector clocks, resolution records
├── cs-sync        Sync engine: pull/diff/apply/push, conflict resolution
├── cs-ui          Interactive terminal conflict resolver
└── cs-cli         The `config-sync` binary (init/add/list/sync/recover/doctor)
```

## License

Dual-licensed under MIT or Apache-2.0, at your option.

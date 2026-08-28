# config-sync

Sync your config files across machines with **post-quantum end-to-end encryption**.

config-sync encrypts your dotfiles and configs with hybrid ML-KEM-768 + X25519
key encapsulation and XChaCha20-Poly1305 AEAD, then syncs the ciphertext to your
choice of cloud storage (S3, Google Drive, OneDrive, Proton Drive, iCloud via
WebDAV, or a local folder). Your cloud provider never sees plaintext.

## Features

- **Post-quantum E2E encryption** — hybrid ML-KEM-768 (NIST FIPS 203, pure
  Rust) + X25519, per-file DEK, XChaCha20-Poly1305 AEAD.
  Harvest-now-decrypt-later safe.
- **Tamper-evident sync** — the sync manifest is sealed with the same
  envelope *and* Ed25519-signed under the vault key: a malicious store cannot
  read your file inventory, forge entries, or roll state back undetected.
  Downloaded blobs are verified against their content hashes before touching
  disk.
- **6 cloud backends** — S3, Google Drive, OneDrive, WebDAV (iCloud /
  Nextcloud / ownCloud / Synology / box.com), Proton Drive (folder + gateway),
  plus local filesystem.
- **Versioned sync** — content-addressed blobs + a versioned manifest with
  vector clocks, monotonic versions, and optimistic concurrency (CAS).
- **Interactive conflict resolution** — latest-wins / prompt / manual policies,
  with a terminal resolver (dialoguer); deletions propagate without
  resurrection.
- **Key recovery that actually restores access** — every device derives its
  keys from one root identity key (RIK), so recovering the RIK (BIP-39
  mnemonic, Shamir k-of-n with fingerprint verification, or a
  passphrase-protected cloud bundle) re-derives the keys and decrypts the
  whole vault on a brand-new machine.
- **Biometrics** — Touch ID/Face ID gating on macOS, fprintd on Linux; plain
  OS keychain elsewhere. Disable with `--no-biometrics`.
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
| Fedora / RHEL / openSUSE | dnf / zypper (.rpm) | `sudo dnf install config-sync-*.rpm` or `sudo zypper install config-sync-*.rpm` |
| Alpine | apk | `apk add --allow-untrusted config-sync-*.apk` |
| Void Linux | xbps | `xbps-install config-sync` |
| Arch Linux | AUR | `yay -S config-sync-bin` |
| Gentoo | Portage (ebuild) | `emerge config-sync-bin` |
| Any (mise) | mise | `mise use -g ubi:gregnazario/config-sync` |
| Windows | Chocolatey | `choco install config-sync` |
| Windows | WinGet | `winget install gregnazario.config-sync` |
| Windows | Scoop | `scoop install config-sync` |
| NixOS | Nix | `nix run github:gregnazario/config-sync` |
| Linux (portable) | Flatpak | `flatpak install config-sync` |
| Linux (portable) | Snap | `sudo snap install config-sync --classic` |
| Linux (portable) | AppImage | `chmod +x config-sync-*.AppImage && ./config-sync-*.AppImage` |

### Build from source

```sh
# Requires: Rust 1.85+ (ML-KEM is pure Rust; no C toolchain needed)
cargo build --release
# Binary: target/release/config-sync

# Optional cloud backends:
cargo build --release --features cs-storage/webdav,cs-storage/gdrive,cs-storage/onedrive
```

## Quick start

```sh
# Initialize the vault (prints the RIK fingerprint — record it)
config-sync init

# Register a config file to manage
config-sync add vim ~/.vimrc --policy latest-wins

# Sync to the remote store (push + pull)
config-sync sync

# Create recovery material (mnemonic shown once / cloud bundle / shamir shares)
config-sync recover --provider mnemonic --setup

# Diagnose the setup
config-sync doctor
```

A second machine joins by recovering the same vault: `config-sync init`,
then `config-sync recover --provider mnemonic` (or cloud/shamir), then `add`
+ `sync` — it decrypts everything immediately because all devices derive
their keys from the shared RIK.

See `docs/usage.md` for the full guide, and `docs/cloud-sync-folders.md` for
configuring Proton Drive / iCloud / Dropbox folder sync.

## Example configs

Ready-to-use config snippets for popular tools are in `examples/`. Copy the
ones you want into your `~/.config/config-sync/config.toml`, or use them as
starting points:

| Example | What it syncs | Policy |
|---|---|---|
| [`neovim.toml`](examples/neovim.toml) | init.lua / init.vim (Linux/macOS/Windows paths) | prompt |
| [`tmux.toml`](examples/tmux.toml) | ~/.tmux.conf + XDG config | latest-wins |
| [`zellij.toml`](examples/zellij.toml) | config.kdl + layouts | prompt |
| [`syncthing.toml`](examples/syncthing.toml) | config.xml (settings, not keys) | manual |
| [`git.toml`](examples/git.toml) | ~/.gitconfig | latest-wins |
| [`shell.toml`](examples/shell.toml) | .zshrc + .bashrc + .bash_profile | prompt |
| [`starship.toml`](examples/starship.toml) | starship.toml prompt config | latest-wins |
| [`alacritty.toml`](examples/alacritty.toml) | alacritty.toml (terminal config) | latest-wins |
| [`screen.toml`](examples/screen.toml) | ~/.screenrc | latest-wins |
| [`ssh.toml`](examples/ssh.toml) | ~/.ssh/config (no private keys) | manual |

## Security model

The RIK (root identity key) is the vault: recipient keys and the manifest
signing key are deterministically derived from it, which is why recovery
restores full access. Files are sealed per-version (path + version bound into
the AEAD), stored as content-addressed ciphertext, and verified (blob id,
content hash, size) after download. The manifest leaves the machine only as a
sealed, signed frame; a hostile store can at best deny service. Two residual,
documented limits: a *brand-new* device can be served state replayed within a
7-day freshness window, and Shamir share substitution is only detectable via
the recorded RIK fingerprint.

## Architecture

```
config-sync
├── cs-crypto      Hybrid PQ+classic KEM, per-file DEK, AEAD envelope,
│                  RIK key derivation, manifest signing (Ed25519)
├── cs-keys        Keychain + biometrics, device identity, recovery providers
├── cs-storage     RemoteStore trait: S3, Google Drive, OneDrive, WebDAV,
│                  Proton Drive, local-fs, in-memory
├── cs-config      Versioned TOML config with per-machine path maps
├── cs-manifest    Versioned manifest, vector clocks, resolution records
├── cs-sync        Sync engine: pull/diff/apply/push, conflict resolution,
│                  sealed+signed manifest transport
├── cs-ui          Interactive terminal conflict resolver
└── cs-cli         The `config-sync` binary (init/add/list/sync/recover/doctor)
```

## License

Dual-licensed under MIT or Apache-2.0, at your option.

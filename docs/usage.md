# config-sync — usage

`config-sync` is a cross-platform CLI that syncs your config files across
machines with post-quantum end-to-end encryption. This document covers the
binary's commands and a typical workflow.

## Build

```sh
cargo build --release          # default: local-fs store + OS keychain + terminal resolver
# Optional cloud backends (each behind a feature):
cargo build --release --features cs-storage/webdav   # iCloud/Nextcloud/ownCloud/Synology/box
cargo build --release --features cs-storage/gdrive   # Google Drive
cargo build --release --features cs-storage/proton   # Proton Drive
cargo build --release --features cs-storage/s3       # S3 / S3-compatible
```

The binary is `target/release/config-sync`.

## Commands

```
config-sync init [--host <name>]
config-sync add  <name> <path> [--policy latest-wins|prompt|manual]
config-sync list
config-sync sync [--non-interactive]
config-sync recover --provider mnemonic|shamir|cloud
config-sync doctor
config-sync --config-dir <dir> <command>      # override the config directory
config-sync --no-biometrics <command>         # disable Touch ID gating
```

## Typical first-device workflow

```sh
# 1. Initialize: generates your device identity (stored in the OS keychain by
#    default) and a starter config at ~/.config/config-sync/config.toml
config-sync init

# 2. Register a config file to manage, with a per-set conflict policy
config-sync add vim ~/.vimrc --policy latest-wins
config-sync add git ~/.gitconfig --policy prompt

# 3. Sync to the remote store (push local changes, pull remote changes,
#    resolve conflicts interactively unless --non-interactive)
config-sync sync
```

## Adding a second device

After `init` on the new machine, run the **add-device enrollment ceremony**
(cycle-2 spec) so the new device shares your identity, then `config-sync add`
the same logical configs and `config-sync sync` to pull them down decrypted.

## Recovery (lost device)

If you lose a machine, recover on a new one from a backup you set up earlier:

```sh
# Mnemonic (24 BIP-39 words you transcribed when setting up recovery)
config-sync recover --provider mnemonic

# Cloud bundle (passphrase-protected bundle uploaded to a store)
config-sync recover --provider cloud
```

## Diagnostics

```sh
config-sync doctor
```

Checks config presence, device identity, the local store directory, and the
detected platform.

## Where things live

| Platform | Default config dir |
|---|---|
| macOS / Linux / FreeBSD | `~/.config/config-sync/` |
| Windows | `%APPDATA%\config-sync\` |

Layout under the config dir:

```
config.toml      # versioned TOML config (managed configs + storage backends)
manifest.bin     # local copy of the sync manifest (vector clocks, entries)
identity.bin     # device identity (only when built without the keyring feature)
store/           # default local-fs remote store
```

With the default `keyring-store` feature, `identity.bin` is replaced by an
entry in the OS keychain (macOS Keychain / Windows Credential Manager / Linux
Secret Service), gated by biometrics where the platform supports it.

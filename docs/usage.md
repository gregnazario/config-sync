# config-sync — usage

`config-sync` is a cross-platform CLI that syncs your config files across
machines with post-quantum end-to-end encryption. This document covers the
binary's commands, the multi-device workflow, recovery, and what the various
sync errors mean.

## Build

```sh
cargo build --release          # default: local-fs store + OS keychain + terminal resolver
# Optional cloud backends (each behind a feature):
cargo build --release --features cs-storage/webdav   # iCloud/Nextcloud/ownCloud/Synology/box
cargo build --release --features cs-storage/gdrive   # Google Drive
cargo build --release --features cs-storage/proton   # Proton Drive (HTTP gateway)
cargo build --release --features cs-storage/s3       # S3 / S3-compatible

# Fully local build (no keychain dependencies; identity kept in a 0600 file):
cargo build --release --no-default-features --features terminal
```

The binary is `target/release/config-sync`.

## Commands

```
config-sync init [--host <name>]
config-sync add  <name> <path> [--policy latest-wins|prompt|manual]
config-sync list
config-sync sync [--non-interactive]
config-sync recover --provider mnemonic|shamir|cloud [--setup]
config-sync doctor
config-sync --config-dir <dir> <command>      # override the config directory
config-sync --no-biometrics <command>         # disable Touch ID gating
```

## Typical first-device workflow

```sh
# 1. Initialize: generates your vault identity (a random root identity key,
#    the RIK, stored in the OS keychain by default) and a starter config at
#    ~/.config/config-sync/config.toml. Prints the vault's RIK fingerprint —
#    write it down.
config-sync init

# 2. Register a config file to manage, with a per-set conflict policy
config-sync add vim ~/.vimrc --policy latest-wins
config-sync add git ~/.gitconfig --policy prompt

# 3. Sync to the remote store (push local changes, pull remote changes,
#    resolve conflicts interactively unless --non-interactive)
config-sync sync

# 4. Create recovery material so a lost device doesn't lose the vault
#    (mnemonic: 24 BIP-39 words shown ONCE; cloud: passphrase-protected
#    bundle; shamir: k-of-n shares to distribute). See "Recovery" below.
config-sync recover --provider mnemonic --setup
```

## Adding a second device

Every device derives the same encryption keys from the vault's RIK, so a new
machine joins by **recovering the RIK** — no identity files to copy:

```sh
# On the new machine:
config-sync init                     # creates a throwaway identity + config
config-sync recover --provider mnemonic   # (or cloud / shamir)
#   → you'll be asked for the recovery secret, asked to confirm replacing
#     the throwaway identity (the old one is backed up to
#     identity.backup.bin), and shown the recovered RIK fingerprint.
#     VERIFY it matches the fingerprint printed by `init` on the first
#     device — a mismatch means the recovery material was substituted.

config-sync add vim ~/.vimrc --policy latest-wins   # same logical names
config-sync sync                     # pulls and decrypts everything
```

Point both devices' config at the same store (see
`docs/cloud-sync-folders.md` for store configuration).

## Recovery

### Setting up (`recover --setup`)

Run on a device that already holds the vault identity:

| Provider | What you get | What to do with it |
|---|---|---|
| `mnemonic` | 24 BIP-39 words printed **once**; bundle written to `recovery/mnemonic.bundle` (0600) | Transcribe the words on paper. Copy the bundle anywhere you can reach when recovering (any store works — it's ciphertext). |
| `cloud` | Passphrase-protected bundle written to `recovery/cloud.bundle` | Upload the bundle to any cloud location. Keep the passphrase (min 12 chars) separately. |
| `shamir` | k hex-encoded shares printed to the terminal; nothing written to disk | Store each share in a **different** location (devices, providers, paper). Record the RIK fingerprint. |

All providers seal the RIK; the fingerprint shown at setup (and by `init`)
is what lets you detect substituted recovery material at recover time.

### Recovering

```sh
config-sync recover --provider mnemonic    # paste the 24 words (input hidden)
config-sync recover --provider cloud       # passphrase (input hidden)
config-sync recover --provider shamir      # interactive: threshold, k shares
                                           # (hidden), optional fingerprint
```

After recovery the device re-derives the vault's recipient keys from the RIK
and can immediately decrypt every blob the vault has ever sealed. If an
identity already exists on the device you will be asked to confirm the
replacement, and the previous identity is backed up to `identity.backup.bin`.

**Always compare the recovered fingerprint** with the one recorded at
setup/`init`. For mnemonic and cloud recovery a wrong secret fails cleanly on
its own; the fingerprint check is what catches substituted *Shamir shares*
(it is optional for shamir, but skipping it means a substituted share set is
undetectable).

## Diagnostics

```sh
config-sync doctor
```

Checks config presence, device identity, the local store directory, and the
detected platform.

## Sync errors and what they mean

All integrity failures fail closed — nothing is written, deleted, or pushed
when a check fails.

| Error | Meaning | What to do |
|---|---|---|
| `signature is invalid ... different vault` | The store's manifest was sealed by another vault's keys (or tampered with). | Check that `--config-dir` and the store path belong to this vault. |
| `older than the last one seen locally ... possible rollback` | The store served a manifest version behind what this device has already seen. | If *you* deliberately reset the store, remove the local `manifest.bin` too, then sync. Otherwise investigate the store. |
| `stale (sealed outside the freshness window)` | A device with no prior history was served a manifest sealed more than 7 days ago. | Only fresh/recovered devices use this check; on a genuine vault, sync once from an existing device or verify the store contents. |
| `store has no manifest but the local cache has sync history` | The local `manifest.bin` references history the store doesn't have — wrong store path, or the store was reset while the local cache wasn't. | Point at the right store, or remove `manifest.bin` knowingly (local files will re-upload). |
| `belongs to a DIFFERENT vault` (local cache) | `manifest.bin` carries a fingerprint header from another vault. | Remove `manifest.bin` knowingly to re-seed. |

## Where things live

| Platform | Default config dir |
|---|---|
| macOS / Linux / FreeBSD | `~/.config/config-sync/` |
| Windows | `%APPDATA%\config-sync\` |

Layout under the config dir (created `0700`; files `0600`):

```
config.toml           # versioned TOML config (managed configs + storage backends)
manifest.bin          # local sync-manifest cache, bound to this vault by a
                      # RIK-fingerprint header (CSLM1); vector clocks, entries
identity.bin          # device identity (only when built without the keyring
                      # feature); the RIK + seed-form private keys
identity.backup.bin   # previous identity, kept when `recover` replaces one
recovery/             # bundles created by `recover --setup` (mnemonic, cloud)
store/                # default local-fs remote store (ciphertext only)
```

With the default `keyring-store` feature, `identity.bin` is replaced by an
entry in the OS keychain (macOS Keychain / Windows Credential Manager / Linux
Secret Service). Biometric gating (Touch ID prompt on secret release) is
enforced on macOS; on other platforms the store falls back to the plain
keychain. `--config-dir` profiles use separate keychain entries, so multiple
vaults on one machine cannot read or overwrite each other's identities.

On the store side you will see only opaque files: `blobs/<hex>` +
`blobs/<hex>.body` (ciphertext), per-object `.version` sidecars and a
`.cas.lock` file (local-fs concurrency control), and `manifest.json` — a
sealed, Ed25519-signed frame (`CSMAN1`) whose contents the provider cannot
read or forge.

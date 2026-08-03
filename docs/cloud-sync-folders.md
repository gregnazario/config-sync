# Syncing through cloud-provider folders (Proton Drive, iCloud, Dropbox, …)

config-sync's `local-fs` store can write its encrypted blobs directly into a
folder that a cloud provider's own desktop app syncs. This is the **simplest
and most robust** way to use Proton Drive, iCloud Drive, Dropbox, OneDrive, or
Syncthing as an upload location: no reverse-engineered API, no provider SDK,
no fidelity gaps — the provider's app handles the upload, and config-sync only
ever writes ciphertext.

## How it works

1. Install the provider's desktop app (e.g. the Proton Drive app, iCloud,
   Dropbox) and sign in.
2. Note the path of its synced folder.
3. Point config-sync's store at a subfolder inside it.
4. `config-sync sync` writes encrypted blobs to that folder; the provider's app
   uploads them. On your other machines, the app downloads them and
   config-sync decrypts.

The blobs are always ciphertext (post-quantum hybrid ML-KEM-768 + X25519 +
XChaCha20-Poly1305), so the provider never sees plaintext — even though the
provider does the transporting.

## Configure it

Edit `~/.config/config-sync/config.toml`:

```toml
schema_version = 1

[identity]
device_id = "..."

[[storage.backend]]
name = "local"
kind = "local-fs"
path = "~/Proton Drive/config-sync"   # any synced folder

[storage]
primary = "local"
```

Then:

```sh
config-sync sync
```

## Provider folder paths

| Provider | Default synced-folder path | Notes |
|---|---|---|
| **Proton Drive** | `~/Proton Drive/` (macOS/Linux), `%USERPROFILE%\Proton Drive\` (Windows) | The official Proton Drive desktop app syncs E2E; config-sync adds a second E2E layer (PQ), so the blobs are double-encrypted. |
| **iCloud Drive** | `~/Library/Mobile Documents/com~apple~CloudDocs/` (macOS) | Built in on macOS. |
| **Dropbox** | `~/Dropbox/` | |
| **OneDrive** | `~/OneDrive/` (macOS/Linux), `%USERPROFILE%\OneDrive\` (Windows) | |
| **Syncthing** | whatever folder you configure | Self-hosted; no account needed. |

## Why this is the recommended Proton Drive integration

Proton Drive's native protocol is an undocumented, layered end-to-end-encrypted
API over Proton's account/session system, with no stable public surface and no
maintained Rust SDK. Rather than reverse-engineer it (fragile, unverifiable
without a live account, prone to breaking on every Proton change), config-sync
uses the **integration point Proton itself publishes for third parties**: the
synced folder exposed by the official Proton Drive desktop app. This is the
same approach tools like rclone and Cryptomator recommend for Proton Drive.

config-sync also ships an HTTP-gateway `proton` backend (`--features
cs-storage/proton`) for cases where you want to talk to a Proton-compatible
gateway directly without the desktop app — but for most users the synced-folder
approach above is simpler and more reliable.

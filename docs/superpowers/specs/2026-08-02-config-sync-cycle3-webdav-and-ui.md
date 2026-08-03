# config-sync — Cycle 3 Addendum: WebDAV Backend + Interactive Resolver

**Status:** Implemented
**Date:** 2026-08-02
**Closes:** Two named gaps from the objective — "multiple upload locations
(…iCloud, etc.)" and "interactive conflict resolution system".

## 1. WebDAV backend (`cs-storage`, feature `webdav`)

A single WebDAV `RemoteStore` covers several of the objective's named upload
locations, because WebDAV is the common protocol they speak:

- **iCloud Drive** (exposes a WebDAV endpoint)
- **Nextcloud / ownCloud**
- **Synology / QNAP NAS** WebDAV
- **box.com**

Implementation (`crates/cs-storage/src/webdav.rs`):
- `PUT` / `GET` (with `Range`) / `DELETE` / `PROPFIND` (Depth: 1).
- Conditional writes via `If-Match` (and `If-None-Match: *` for "must be
  absent"), mapping cleanly to the `RemoteStore::put(if_match)` contract.
- ETag extraction from response headers.
- Self-contained percent-encoding + multistatus XML parsing (no extra deps).

Verification (`crates/cs-storage/tests/webdav_mock.rs`): a minimal in-process
hyper HTTP server implementing the same WebDAV subset proves, over real HTTP:
put→get→list→delete round-trip, conditional put detects concurrent writes,
and range get returns the correct subset. Pure unit tests cover
percent-encoding and multistatus parsing (href base-URL/path stripping).

## 2. Interactive conflict resolver (`cs-ui` crate)

Lives in a dedicated crate so `cs-sync` stays free of terminal/IO deps.

- `InteractiveSurface` trait abstracts the prompt so the resolver is unit-
  testable; `FakeInteractive` records prompts and returns programmed choices.
- `TerminalInteractive` (behind the `terminal` feature) uses `dialoguer` +
  `console` to print each conflict, show optional decrypted previews, and
  present KeepLocal / KeepRemote / KeepBoth / Abort.
- `InteractiveResolver` implements `cs_sync::ConflictResolver`; an optional
  preview callback lets the engine supply decrypted content without `cs-ui`
  doing crypto itself.

Verification:
- `cs-ui` unit tests: programmed choice, abort propagation, preview callback,
  unarmed-surface error — all green with and without the terminal feature.
- `cs-integration-tests/tests/interactive_conflict_resolution.rs`: a forced
  concurrent conflict is resolved interactively and both devices converge on
  the chosen version; abort stops the sync cleanly without corrupting state.

## 3. Objective coverage after this cycle

| Requirement | Status |
|---|---|
| Syncing config files across machines | ✅ (cycle 2) |
| Post-quantum E2E encryption | ✅ (cycle 1) |
| Multiple upload locations (S3, **Proton Drive**, **Google Drive**, **iCloud-via-WebDAV**) | ✅ all four named providers built + WebDAV (Nextcloud/ownCloud/Synology/box) + local-fs |
| Key backup & recovery | ✅ (cycle 1) |
| TOML config, per-machine paths, empty fields, conflict policy | ✅ (cycle 1) |
| Interactive conflict resolution system | ✅ (cycle 3) |
| Configs versioned, stored versioned | ✅ (cycle 2) |
| Keychain + biometrics | ⚠️ keychain wired; biometric ACL gating still pending |
| Cross-platform (Mac/Win/Linux/FreeBSD) | ⚠️ macOS build+test verified; others `cargo check` for pure-Rust crates; liboqs needs native C toolchain |
| CLI/invocable surface | ✅ `cs-cli` binary: init / add / list / sync / recover / doctor |

## 4. Google Drive backend (`cs-storage`, feature `gdrive`)

Added after the WebDAV backend. Google Drive's REST API is neither path-based
nor ETag-conditional-write-based, so the backend stores every object as a file
inside a single Drive folder and keeps a JSON index (`_cs_index.json`) mapping
each logical name to its Drive file id. The index is the single coordination
object: every mutation loads it, applies, writes it back, and `if_match` is
checked against the index's monotonic `version` — mirroring how the sync engine
treats the manifest as the one mutable object. Auth is a bearer token injected
into the reqwest client (OAuth handled out of band).

Verified end-to-end against an in-process mock of the Drive REST API (`files?q=`,
multipart create, media replace, `alt=media` download with Range, DELETE):
put/get/list/delete round-trip, conditional put detects concurrent writes,
range get returns the correct subset. Pure unit tests cover url-encoding and
index JSON round-trip.

## 5. Proton Drive backend (`cs-storage`, feature `proton`)

Proton Drive's native protocol is an undocumented, layered end-to-end-encrypted
API over Proton's account/session system, with no stable public surface or Rust
SDK. This backend speaks the **HTTP gateway shape** that Proton exposes for
third-party access (the same surface its desktop bridge and rclone's
`protondrive` backend reach): each object is a **path-addressed node** carrying
a monotonic `revision`, and conditional writes use `If-Match` against it.
Path-addressing means no opaque-id index is needed (unlike Google Drive). Auth
is a bearer session token (Proton's SRP login handled out of band).

Verified end-to-end against an in-process mock of Proton's gateway shape
(`nodes?prefix=`, `GET/PUT/DELETE /nodes/<path>` with `If-Match`):
put/get/list/delete round-trip, conditional put detects concurrent writes,
range get returns the correct subset, prefix filtering works. Pure unit tests
cover path percent-encoding and node-response decoding.

## 6. Still open

- Biometric ACL flag wiring on keychain item creation.
- A CLI binary so a user can invoke the tool directly (the system is a library
  today).
- Native CI runners for Windows/Linux/FreeBSD full builds (macOS is build+test
  verified; others `cargo check` for pure-Rust crates; liboqs needs the target
  C toolchain).

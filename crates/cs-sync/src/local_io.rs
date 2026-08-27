//! Local-file ↔ ciphertext bridge. Reads a managed file from disk, seals it
//! into a header blob + body blob (content-addressed), and writes decrypted
//! plaintext back to disk on pull.

use crate::SyncError;
use cs_crypto::{open, seal, Aad, OpenInput, RecipientKeys, RecipientSecrets};
use cs_manifest::{ConfigPath, Entry, Sha256, VectorClock};
use std::path::Path;
use std::time::SystemTime;

/// A sealed file: the envelope header blob (which carries the wrapped DEK),
/// the body blob (the AEAD ciphertext), and the content id of the header
/// (which is the Entry's `blob_id`).
pub struct SealedFile {
    pub header_blob: Vec<u8>,
    pub body_blob: Vec<u8>,
    pub header_id: Sha256,
}

/// Seal already-read plaintext bytes into a [`SealedFile`] plus a manifest
/// [`Entry`]. This avoids re-reading the file from disk when the caller has
/// already read it (e.g. for hash detection in `scan_local`).
pub fn seal_plaintext(
    plaintext: &[u8],
    logical_path: &ConfigPath,
    aad_version: u64,
    clock: VectorClock,
    recip: &RecipientKeys,
    modified: SystemTime,
) -> Result<(Entry, SealedFile), SyncError> {
    let size = plaintext.len() as u64;
    let aad = Aad {
        path: logical_path.0.clone(),
        version: aad_version,
    };
    let out = seal(plaintext, &aad, recip)?;
    let header_id = Sha256::of(&out.header);
    let content_hash = Sha256::of(plaintext);
    let entry = Entry {
        blob_id: header_id.clone(),
        content_hash,
        aad_version,
        clock,
        size,
        modified,
        deleted: false,
    };
    Ok((
        entry,
        SealedFile {
            header_blob: out.header,
            body_blob: out.body,
            header_id,
        },
    ))
}

/// Read a file from disk and seal it into a [`SealedFile`] plus a manifest
/// [`Entry`]. Thin wrapper around [`seal_plaintext`] that reads from disk.
pub fn read_and_seal(
    disk_path: &Path,
    logical_path: &ConfigPath,
    aad_version: u64,
    clock: VectorClock,
    recip: &RecipientKeys,
) -> Result<(Entry, SealedFile), SyncError> {
    let plaintext = std::fs::read(disk_path)?;
    let modified = std::fs::metadata(disk_path)?
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH);
    seal_plaintext(
        &plaintext,
        logical_path,
        aad_version,
        clock,
        recip,
        modified,
    )
}

/// Open a sealed header+body pair into plaintext, binding the entry's
/// `aad_version` and the logical path into the AEAD AAD.
pub fn open_sealed(
    header: &[u8],
    body: &[u8],
    logical_path: &ConfigPath,
    entry: &Entry,
    secrets: &RecipientSecrets,
) -> Result<Vec<u8>, SyncError> {
    let aad = Aad {
        path: logical_path.0.clone(),
        version: entry.aad_version,
    };
    Ok(open(OpenInput { header, body }, &aad, secrets)?)
}

/// Write plaintext back to disk, creating parent directories as needed.
///
/// Security properties:
/// - **Atomic**: content is written to a temp file in the same directory and
///   renamed over the target, so a crash mid-write can never leave a truncated
///   config behind (which the next sync would then seal and push everywhere).
/// - **No symlink traversal**: `rename` replaces the target path entry itself
///   rather than following a symlink planted at it.
/// - **Private**: new files are created 0600 on Unix (decrypted configs may
///   hold secrets); an existing file's permissions are preserved.
pub fn write_plaintext(disk_path: &Path, plaintext: &[u8]) -> Result<(), SyncError> {
    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = disk_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config-sync-file".to_string());
    let tmp_path = {
        // Unique per call so concurrent writes to one target don't collide.
        let mut buf = [0u8; 4];
        let _ = getrandom::fill(&mut buf);
        disk_path.with_file_name(format!(".{}.{}.csync-tmp", file_name, hex::encode(buf)))
    };

    #[cfg(unix)]
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(plaintext)?;
        f.sync_all()?;
        drop(f);
        Ok(())
    })();

    #[cfg(not(unix))]
    let write_result = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        f.write_all(plaintext)?;
        f.sync_all()?;
        drop(f);
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(SyncError::Io(e));
    }

    // Preserve an existing target's permissions (a user's 0644 dotfile stays
    // 0644); fresh files keep the temp file's 0600.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(disk_path) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &tmp_path,
            std::fs::Permissions::from_mode(meta.permissions().mode()),
        );
    }

    std::fs::rename(&tmp_path, disk_path)?;
    Ok(())
}

// ---- sealed remote manifest ----------------------------------------------
//
// The manifest is the trust anchor for every pull, deletion, and conflict
// decision, and it lives on untrusted storage. It is therefore sealed with the
// same hybrid-KEM envelope as file blobs: the store sees only ciphertext, and
// a hostile store can neither forge entries (tombstone injection, blob swaps)
// nor read the synced file inventory.

/// Logical AAD path binding the manifest envelope. A constant version is
/// used: replay resistance comes from `manifest_version` inside the
/// authenticated payload plus the engine's local monotonic check.
pub const MANIFEST_AAD_PATH: &str = "manifest";

fn manifest_aad() -> Aad {
    Aad {
        path: MANIFEST_AAD_PATH.to_string(),
        version: 0,
    }
}

/// Sealed-manifest frame magic.
const MANIFEST_FRAME_MAGIC: &[u8; 6] = b"CSMAN1";
/// Fixed prefix size: magic(6) + version(8) + sealed_at(8) + header_len(4).
const MANIFEST_FRAME_PREFIX: usize = 26;

/// A sealed manifest older than this is rejected even if its signature is
/// valid: it bounds how far a hostile store can rewind state for a device
/// that has no local history to anchor on. Generous enough for devices that
/// sync weekly.
pub const MAX_MANIFEST_AGE_SECS: u64 = 7 * 24 * 60 * 60;
/// Tolerance for clock skew between the sealing device and this one.
pub const MAX_MANIFEST_FUTURE_SECS: u64 = 24 * 60 * 60;

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seal and sign a manifest into a single framed object:
/// `magic || u64 version || u64 sealed_at || u32 header_len || header || body || sig64`,
/// where the Ed25519 signature (key derived from the RIK) covers everything
/// before it. The version and seal time travel *outside* the ciphertext but
/// unforgeably, so any device can reject rolled-back or stale manifests
/// before decrypting.
pub fn seal_manifest(
    m: &cs_manifest::Manifest,
    recip: &RecipientKeys,
    signer: &cs_crypto::ManifestSigningKey,
    now: SystemTime,
) -> Result<Vec<u8>, SyncError> {
    let bytes = m
        .to_bytes()
        .map_err(|e| SyncError::Manifest(format!("manifest encode: {e}")))?;
    let out = seal(&bytes, &manifest_aad(), recip)?;
    let mut framed = Vec::with_capacity(
        MANIFEST_FRAME_PREFIX + out.header.len() + out.body.len() + cs_crypto::MANIFEST_SIG_LEN,
    );
    framed.extend_from_slice(MANIFEST_FRAME_MAGIC);
    framed.extend_from_slice(&m.manifest_version.to_le_bytes());
    framed.extend_from_slice(&unix_secs(now).to_le_bytes());
    framed.extend_from_slice(&(out.header.len() as u32).to_le_bytes());
    framed.extend_from_slice(&out.header);
    framed.extend_from_slice(&out.body);
    let sig = signer.sign(&framed);
    framed.extend_from_slice(&sig);
    Ok(framed)
}

/// Open a framed sealed manifest produced by [`seal_manifest`]. Fails closed
/// on any tampering: the signature is verified against the vault's RIK-derived
/// verifying key, the seal time must be within the freshness window, and the
/// AEAD envelope must authenticate — an unauthenticated, stale, rolled-back,
/// or wrongly-keyed manifest is never returned to the engine.
pub fn open_manifest(
    framed: &[u8],
    secrets: &RecipientSecrets,
    verifying_key: &[u8; cs_crypto::MANIFEST_VERIFYING_KEY_LEN],
    has_local_anchor: bool,
    now: SystemTime,
) -> Result<cs_manifest::Manifest, SyncError> {
    if framed.len() < MANIFEST_FRAME_PREFIX + 24 + cs_crypto::MANIFEST_SIG_LEN {
        return Err(SyncError::Manifest("manifest envelope truncated".into()));
    }
    if &framed[..6] != MANIFEST_FRAME_MAGIC {
        return Err(SyncError::Manifest(
            "remote manifest is not a signed sealed envelope (legacy or tampered store); \
             move the store aside and re-sync to re-seal it"
                .into(),
        ));
    }
    let outer_version = u64::from_le_bytes(framed[6..14].try_into().expect("8 bytes"));
    let sealed_at = u64::from_le_bytes(framed[14..22].try_into().expect("8 bytes"));
    let hdr_len = u32::from_le_bytes(framed[22..26].try_into().expect("4 bytes")) as usize;
    // checked_add: on 32-bit targets an attacker-chosen hdr_len could
    // otherwise overflow usize and wrap into a panicking slice below.
    let header_end = MANIFEST_FRAME_PREFIX
        .checked_add(hdr_len)
        .ok_or_else(|| SyncError::Manifest("manifest envelope truncated".into()))?;
    let sig_start = framed.len() - cs_crypto::MANIFEST_SIG_LEN;
    if hdr_len == 0 || header_end > sig_start {
        return Err(SyncError::Manifest("manifest envelope truncated".into()));
    }

    // Signature over everything before it — magic, version, seal time,
    // lengths, and both ciphertext blobs. Verified BEFORE any decryption.
    let sig: &[u8; cs_crypto::MANIFEST_SIG_LEN] = framed[sig_start..].try_into().expect("64 bytes");
    if !cs_crypto::verify_manifest_signature(verifying_key, &framed[..sig_start], sig) {
        return Err(SyncError::Manifest(
            "remote manifest signature is invalid; store is tampered or belongs to a \
             different vault"
                .into(),
        ));
    }

    // Freshness: the *stale* window only applies to devices with no trusted
    // local anchor (fresh or recovered) — it is their only replay bound. A
    // device with local history is anchored by the manifest-version
    // monotonicity check instead, and MUST NOT be locked out just because
    // the vault was idle for more than the window (an entirely normal state
    // for config syncing). The future-skew guard applies to everyone.
    let now_secs = unix_secs(now);
    if sealed_at > now_secs.saturating_add(MAX_MANIFEST_FUTURE_SECS) {
        return Err(SyncError::Manifest(
            "remote manifest has a seal time too far in the future; wrong system clock \
             or tampered store"
                .into(),
        ));
    }
    if !has_local_anchor && sealed_at < now_secs.saturating_sub(MAX_MANIFEST_AGE_SECS) {
        return Err(SyncError::Manifest(
            "remote manifest is stale (sealed outside the freshness window); \
             possible rollback by the store"
                .into(),
        ));
    }

    let header = &framed[MANIFEST_FRAME_PREFIX..header_end];
    let body = &framed[header_end..sig_start];
    let bytes = open(OpenInput { header, body }, &manifest_aad(), secrets)
        .map_err(|e| SyncError::Manifest(format!("remote manifest failed authentication: {e}")))?;
    let m = cs_manifest::Manifest::from_bytes(&bytes)
        .map_err(|e| SyncError::Manifest(format!("manifest decode: {e}")))?;
    // The signed outer version must agree with the encrypted inner one.
    if m.manifest_version != outer_version {
        return Err(SyncError::Manifest(
            "manifest version mismatch between frame and payload".into(),
        ));
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cs_crypto::generate_recipient_keypair;
    use cs_manifest::DeviceId;
    use tempfile::TempDir;

    #[test]
    fn seal_then_open_round_trips_via_files() {
        let (pk, sk) = generate_recipient_keypair();
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src.txt");
        std::fs::write(&src, b"set nu\n").unwrap();
        let path = ConfigPath::new("vim/.vimrc");
        let mut clock = VectorClock::new();
        clock.bump(&DeviceId::new("A"));
        let (entry, sf) = read_and_seal(&src, &path, 1, clock, &pk).unwrap();
        assert_eq!(entry.size, 7); // "set nu\n" is 7 bytes
        assert_eq!(entry.blob_id, sf.header_id);
        let pt = open_sealed(&sf.header_blob, &sf.body_blob, &path, &entry, &sk).unwrap();
        let dst = dir.path().join("out").join("dst.txt");
        write_plaintext(&dst, &pt).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"set nu\n");
    }

    #[test]
    fn wrong_logical_path_fails_open() {
        // AAD binds the path; opening under a different logical path must fail.
        let (pk, sk) = generate_recipient_keypair();
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("x.txt");
        std::fs::write(&src, b"secret").unwrap();
        let path = ConfigPath::new("vim/x");
        let wrong = ConfigPath::new("vim/y");
        let (entry, sf) = read_and_seal(&src, &path, 1, VectorClock::new(), &pk).unwrap();
        assert!(open_sealed(&sf.header_blob, &sf.body_blob, &wrong, &entry, &sk).is_err());
    }

    #[test]
    fn header_and_body_are_distinct_content() {
        let (pk, _sk) = generate_recipient_keypair();
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("x");
        std::fs::write(&src, b"data").unwrap();
        let (_e, sf) =
            read_and_seal(&src, &ConfigPath::new("p"), 1, VectorClock::new(), &pk).unwrap();
        assert!(!sf.header_blob.is_empty());
        assert!(!sf.body_blob.is_empty());
        assert_ne!(sf.header_blob, sf.body_blob);
    }

    #[cfg(unix)]
    #[test]
    fn write_plaintext_creates_private_files_and_preserves_existing_modes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("creds");
        write_plaintext(&target, b"secret").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "decrypted files must be created owner-only"
        );
        // An existing user-chosen mode is preserved.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_plaintext(&target, b"secret2").unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        // No temp files are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("csync-tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn write_plaintext_replaces_planted_symlinks_instead_of_following() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let target = dir.path().join("managed");
        symlink(&victim, &target).unwrap();
        write_plaintext(&target, b"pulled").unwrap();
        // The symlink itself is replaced; the victim is untouched.
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert_eq!(std::fs::read(&target).unwrap(), b"pulled");
    }

    #[test]
    fn sealed_manifest_round_trips_and_fails_closed() {
        use cs_crypto::{generate_rik, ManifestSigningKey};
        use cs_manifest::DeviceId;
        let rik = generate_rik().unwrap();
        let (pk, sk) = cs_crypto::derive_recipient_keypair(&rik);
        let signer = ManifestSigningKey::derive_from_rik(&rik);
        let mut m = cs_manifest::Manifest::new("A");
        m.clock.bump(&DeviceId::new("A"));
        m.entries.insert(
            ConfigPath::new("vim/.vimrc"),
            cs_manifest::Entry {
                blob_id: cs_manifest::Sha256::of(b"x"),
                content_hash: cs_manifest::Sha256::of(b"x"),
                aad_version: 1,
                clock: m.clock.clone(),
                size: 1,
                modified: SystemTime::UNIX_EPOCH,
                deleted: false,
            },
        );
        m.manifest_version = 3;
        let now = SystemTime::UNIX_EPOCH;
        let sealed = seal_manifest(&m, &pk, &signer, now).unwrap();
        let vk = signer.verifying_key_bytes();
        let back = open_manifest(&sealed, &sk, &vk, false, now).unwrap();
        assert_eq!(back, m);

        // Wrong identity (different vault keys) fails closed.
        let (other_pk, other_sk, other_signer) = {
            let other_rik = generate_rik().unwrap();
            let k = cs_crypto::derive_recipient_keypair(&other_rik);
            (k.0, k.1, ManifestSigningKey::derive_from_rik(&other_rik))
        };
        let _ = other_pk;
        assert!(open_manifest(&sealed, &other_sk, &vk, false, now).is_err());
        // Wrong verifying key (different vault) fails closed.
        assert!(open_manifest(
            &sealed,
            &sk,
            &other_signer.verifying_key_bytes(),
            false,
            now
        )
        .is_err());
        // Any bit flip fails closed.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(open_manifest(&tampered, &sk, &vk, false, now).is_err());
    }

    #[test]
    fn stale_and_future_manifests_are_rejected() {
        use cs_crypto::{generate_rik, ManifestSigningKey};
        let rik = generate_rik().unwrap();
        let (pk, sk) = cs_crypto::derive_recipient_keypair(&rik);
        let signer = ManifestSigningKey::derive_from_rik(&rik);
        let vk = signer.verifying_key_bytes();
        let m = cs_manifest::Manifest::new("A");
        let now = SystemTime::UNIX_EPOCH;

        // Sealed long in the past: an ANCHORLESS (fresh/recovered) reader
        // rejects it even though it is perfectly signed and encrypted — the
        // freshness window is that device's only replay bound.
        let stale_at = SystemTime::UNIX_EPOCH;
        let sealed = seal_manifest(&m, &pk, &signer, stale_at).unwrap();
        let far_future_reader =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(MAX_MANIFEST_AGE_SECS + 1);
        assert!(open_manifest(&sealed, &sk, &vk, false, far_future_reader).is_err());
        // A reader WITH local history (idle vault) still accepts it: version
        // monotonicity, not staleness, protects that device.
        assert!(open_manifest(&sealed, &sk, &vk, true, far_future_reader).is_ok());

        // Fresh seal is accepted by a same-time reader.
        assert!(open_manifest(&sealed, &sk, &vk, false, stale_at).is_ok());

        // Seal time unreasonably in the future → rejected (clock-skew guard).
        let future_seal =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(MAX_MANIFEST_FUTURE_SECS + 60);
        let sealed_future = seal_manifest(&m, &pk, &signer, future_seal).unwrap();
        assert!(open_manifest(&sealed_future, &sk, &vk, true, now).is_err());
    }

    #[test]
    fn signed_frame_version_mismatch_is_rejected() {
        // A frame whose (correctly signed) outer version disagrees with the
        // encrypted payload's version must fail closed.
        use cs_crypto::{generate_rik, ManifestSigningKey};
        let rik = generate_rik().unwrap();
        let (pk, sk) = cs_crypto::derive_recipient_keypair(&rik);
        let signer = ManifestSigningKey::derive_from_rik(&rik);
        let vk = signer.verifying_key_bytes();
        let m = cs_manifest::Manifest::new("A");
        let now = SystemTime::UNIX_EPOCH;

        let mut sealed = seal_manifest(&m, &pk, &signer, now).unwrap();
        // Corrupt the outer version then re-sign (simulates a signer bug or a
        // vault with mismatched tooling; the frame is "valid" but inconsistent).
        sealed[6..14].copy_from_slice(&99u64.to_le_bytes());
        let sig = signer.sign(&sealed);
        sealed.truncate(sealed.len() - cs_crypto::MANIFEST_SIG_LEN);
        sealed.extend_from_slice(&sig);
        assert!(open_manifest(&sealed, &sk, &vk, true, now).is_err());
    }
}

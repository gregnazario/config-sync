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

/// Read a file from disk and seal it into a [`SealedFile`] plus a manifest
/// [`Entry`]. `clock` becomes the entry's causal clock; the caller bumps it.
pub fn read_and_seal(
    disk_path: &Path,
    logical_path: &ConfigPath,
    aad_version: u64,
    clock: VectorClock,
    recip: &RecipientKeys,
) -> Result<(Entry, SealedFile), SyncError> {
    let plaintext = std::fs::read(disk_path)?;
    let size = plaintext.len() as u64;
    let aad = Aad {
        path: logical_path.0.clone(),
        version: aad_version,
    };
    let out = seal(&plaintext, &aad, recip)?;
    let header_id = Sha256::of(&out.header);
    let content_hash = Sha256::of(&plaintext);
    let entry = Entry {
        blob_id: header_id.clone(),
        content_hash,
        aad_version,
        clock,
        size,
        modified: std::fs::metadata(disk_path)?
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH),
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
pub fn write_plaintext(disk_path: &Path, plaintext: &[u8]) -> Result<(), SyncError> {
    if let Some(parent) = disk_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(disk_path, plaintext)?;
    Ok(())
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
}

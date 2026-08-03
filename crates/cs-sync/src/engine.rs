//! The sync engine: pull remote manifest, diff, apply pulls/conflicts, push
//! new blobs and a conditionally-put manifest. Retries on CAS failure.

use crate::conflict::{resolve_conflict, ConflictResolver, Resolution};
use crate::diff::{diff, DiffOp};
use crate::local_io::{open_sealed, read_and_seal, write_plaintext};
use crate::SyncError;
use bytes::Bytes;
use cs_config::ConflictPolicy;
use cs_crypto::{RecipientKeys, RecipientSecrets};
use cs_manifest::{ConfigPath, DeviceId, Entry, Manifest};
use cs_storage::RemoteStore;
use std::path::PathBuf;
use std::time::SystemTime;

const MANIFEST_KEY: &str = "manifest.json";
const BLOB_PREFIX: &str = "blobs/";
const MAX_CAS_RETRIES: u32 = 3;

#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    pub pulled: Vec<ConfigPath>,
    pub pushed: Vec<ConfigPath>,
    pub conflicts_resolved: Vec<ConfigPath>,
    pub aborted: bool,
}

/// One local managed file: its logical (portable) path, its on-disk location
/// on this machine, and its per-set conflict policy.
pub struct ManagedFile {
    pub logical: ConfigPath,
    pub disk_path: PathBuf,
    pub policy: ConflictPolicy,
}

/// A blob staged for upload: its manifest entry plus the two ciphertext blobs.
struct PendingPush {
    path: ConfigPath,
    entry: Entry,
    header_blob: Vec<u8>,
    body_blob: Vec<u8>,
}

/// Per-call context bundled so the public [`sync`] signature stays small. Holds
/// everything that does not change across CAS retries.
pub struct SyncContext<'a> {
    pub device: &'a DeviceId,
    pub files: &'a [ManagedFile],
    pub recip_keys: &'a RecipientKeys,
    pub recip_secrets: &'a RecipientSecrets,
    pub resolver: Option<&'a dyn ConflictResolver>,
    pub now: SystemTime,
}

// Internal alias kept for readability.
type SyncInputs<'a> = SyncContext<'a>;

fn blob_key(id_hex: &str) -> String {
    format!("{BLOB_PREFIX}{id_hex}")
}

fn blob_body_key(id_hex: &str) -> String {
    format!("{BLOB_PREFIX}{id_hex}.body")
}

async fn fetch_remote_manifest(store: &dyn RemoteStore) -> Result<Manifest, SyncError> {
    match store.get(MANIFEST_KEY).await {
        Ok(bytes) => Manifest::from_bytes(&bytes).map_err(|e| SyncError::Manifest(e.to_string())),
        Err(cs_storage::StorageError::NotFound(_)) => Ok(Manifest::new("remote")),
        Err(e) => Err(e.into()),
    }
}

/// Run one full sync cycle. Pulls, applies, pushes, and retries the manifest
/// CAS up to [`MAX_CAS_RETRIES`] times under contention.
pub async fn sync(
    store: &dyn RemoteStore,
    local: &mut Manifest,
    ctx: &SyncContext<'_>,
) -> Result<SyncReport, SyncError> {
    sync_inner(store, local, ctx).await
}

async fn sync_inner(
    store: &dyn RemoteStore,
    local: &mut Manifest,
    inputs: &SyncInputs<'_>,
) -> Result<SyncReport, SyncError> {
    let mut report = SyncReport::default();

    // Phase 0: scan local files into the manifest. A managed file that exists
    // on disk but is absent from the manifest (or whose content has changed
    // since the recorded entry) becomes a fresh local entry to push. A managed
    // file absent from disk but present in the manifest becomes a tombstone.
    let mut staged_pushes: Vec<PendingPush> = scan_local(local, inputs)?;

    for attempt in 0..MAX_CAS_RETRIES {
        let remote = fetch_remote_manifest(store).await?;
        let ops = diff(local, &remote);

        // Pending pushes discovered during conflict resolution this pass.
        let mut pushes: Vec<PendingPush> = Vec::new();
        let mut aborted = false;

        for op in ops {
            match op {
                DiffOp::PullLocal { path, remote } => {
                    if let Some(mf) = inputs.files.iter().find(|f| f.logical == path) {
                        let hdr = store.get(&blob_key(&remote.blob_id.to_hex())).await?;
                        let body = store.get(&blob_body_key(&remote.blob_id.to_hex())).await?;
                        let pt = open_sealed(&hdr, &body, &path, &remote, inputs.recip_secrets)?;
                        write_plaintext(&mf.disk_path, &pt)?;
                        local.entries.insert(path.clone(), remote.clone());
                        report.pulled.push(path);
                    }
                }
                DiffOp::PullDeletion { path, remote: _ } => {
                    if let Some(mf) = inputs.files.iter().find(|f| f.logical == path) {
                        let _ = std::fs::remove_file(&mf.disk_path);
                    }
                    local.entries.remove(&path);
                }
                DiffOp::PushRemote { path: _, local: _ } => {
                    // Handled by staged_pushes from scan_local; nothing extra.
                }
                DiffOp::PushDeletion { path, local: _ } => {
                    if let Some(mf) = inputs.files.iter().find(|f| f.logical == path) {
                        let _ = std::fs::remove_file(&mf.disk_path);
                    }
                    local.entries.remove(&path);
                }
                DiffOp::InSync { path: _ } => {}
                DiffOp::Conflict {
                    path,
                    local: l,
                    remote: r,
                } => {
                    let mf = inputs
                        .files
                        .iter()
                        .find(|f| f.logical == path)
                        .ok_or_else(|| {
                            SyncError::Manifest(format!("no managed file for {path}"))
                        })?;
                    let conflict = crate::conflict::Conflict {
                        path: path.clone(),
                        local: l.clone(),
                        remote: r.clone(),
                    };
                    let res = resolve_conflict(
                        &conflict,
                        mf.policy,
                        inputs.resolver,
                        local.manifest_version + 1,
                        inputs.now,
                    )?;
                    match res {
                        Resolution::Aborted => {
                            aborted = true;
                            report.aborted = true;
                            break;
                        }
                        Resolution::Resolved { chosen, .. } => {
                            if chosen.blob_id == r.blob_id {
                                let hdr = store.get(&blob_key(&r.blob_id.to_hex())).await?;
                                let body = store.get(&blob_body_key(&r.blob_id.to_hex())).await?;
                                let pt = open_sealed(&hdr, &body, &path, &r, inputs.recip_secrets)?;
                                write_plaintext(&mf.disk_path, &pt)?;
                                local.entries.insert(path.clone(), r.clone());
                                report.pulled.push(path.clone());
                            } else {
                                let mut clk = l.clock.clone();
                                clk.merge(&r.clock);
                                clk.bump(inputs.device);
                                let (entry, sf) = read_and_seal(
                                    &mf.disk_path,
                                    &path,
                                    l.aad_version + 1,
                                    clk,
                                    inputs.recip_keys,
                                )?;
                                pushes.push(PendingPush {
                                    path: path.clone(),
                                    entry,
                                    header_blob: sf.header_blob,
                                    body_blob: sf.body_blob,
                                });
                            }
                            report.conflicts_resolved.push(path);
                        }
                    }
                }
            }
        }

        if aborted {
            return Ok(report);
        }

        // Combine staged pushes (from scan_local) with conflict-driven pushes.
        staged_pushes.extend(pushes);

        // Upload blobs and merge staged entries into the manifest.
        for p in &staged_pushes {
            store
                .put(
                    &blob_key(&p.entry.blob_id.to_hex()),
                    Bytes::from(p.header_blob.clone()),
                    None,
                )
                .await?;
            store
                .put(
                    &blob_body_key(&p.entry.blob_id.to_hex()),
                    Bytes::from(p.body_blob.clone()),
                    None,
                )
                .await?;
            local.entries.insert(p.path.clone(), p.entry.clone());
        }

        // Bump aggregate clock + version, then conditionally-put the manifest.
        local.clock.bump(inputs.device);
        local.manifest_version += 1;
        local.device_id = inputs.device.as_str().to_string();
        let bytes = local
            .to_bytes()
            .map_err(|e| SyncError::Manifest(e.to_string()))?;

        match store.put(MANIFEST_KEY, Bytes::from(bytes), None).await {
            Ok(_etag) => {
                report
                    .pushed
                    .extend(staged_pushes.into_iter().map(|p| p.path));
                return Ok(report);
            }
            Err(cs_storage::StorageError::PreconditionFailed) if attempt + 1 < MAX_CAS_RETRIES => {
                // Another device won the manifest race: re-fetch and re-diff.
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(SyncError::CasRetriesExhausted(MAX_CAS_RETRIES))
}

/// Scan managed files on disk and stage entries/blobs for any that are new or
/// changed, and tombstone any that vanished locally. Tombstones are written
/// straight into `local.entries`.
fn scan_local(
    local: &mut Manifest,
    inputs: &SyncInputs<'_>,
) -> Result<Vec<PendingPush>, SyncError> {
    let mut staged = Vec::new();
    for mf in inputs.files {
        let on_disk = std::fs::read(&mf.disk_path).ok();
        let existing = local.entries.get(&mf.logical).cloned();
        match (on_disk, existing) {
            (Some(plain), Some(prev)) => {
                // Detect real content change via the plaintext hash; sealing is
                // randomized so the ciphertext blob id is not a stable fingerprint.
                let disk_hash = cs_manifest::Sha256::of(&plain);
                if disk_hash == prev.content_hash && !prev.deleted {
                    // Content unchanged; keep prev (don't re-seal or bump).
                    continue;
                }
                let mut clk = prev.clock.clone();
                clk.bump(inputs.device);
                let (entry, sf) = read_and_seal(
                    &mf.disk_path,
                    &mf.logical,
                    prev.aad_version + 1,
                    clk,
                    inputs.recip_keys,
                )?;
                local.entries.insert(mf.logical.clone(), entry.clone());
                staged.push(PendingPush {
                    path: mf.logical.clone(),
                    entry,
                    header_blob: sf.header_blob,
                    body_blob: sf.body_blob,
                });
            }
            (Some(_plain), None) => {
                // Brand-new local file: seed an initial entry from the device's clock.
                let mut clk = local.clock.clone();
                clk.bump(inputs.device);
                let aad_version = 1;
                let (mut entry, sf) = read_and_seal(
                    &mf.disk_path,
                    &mf.logical,
                    aad_version,
                    clk,
                    inputs.recip_keys,
                )?;
                // Ensure the per-path clock strictly advances from empty by bumping
                // once more so a subsequent remote fast-forward is unambiguous.
                entry.clock.bump(inputs.device);
                local.entries.insert(mf.logical.clone(), entry.clone());
                staged.push(PendingPush {
                    path: mf.logical.clone(),
                    entry,
                    header_blob: sf.header_blob,
                    body_blob: sf.body_blob,
                });
            }
            (None, Some(prev)) if !prev.deleted => {
                // File removed locally → tombstone.
                let mut t = prev.clone();
                t.deleted = true;
                t.clock.bump(inputs.device);
                local.entries.insert(mf.logical.clone(), t);
            }
            (None, _) => { /* nothing on disk, nothing tracked */ }
        }
    }
    Ok(staged)
}

#[cfg(test)]
mod engine_tests {
    use super::*;
    use cs_crypto::generate_recipient_keypair;
    use cs_storage::LocalFs;
    use tempfile::TempDir;

    fn mf(dir: &TempDir, name: &str) -> ManagedFile {
        ManagedFile {
            logical: ConfigPath::new(name),
            disk_path: dir.path().join(name),
            policy: ConflictPolicy::LatestWins,
        }
    }

    #[tokio::test]
    async fn first_push_then_pull_converges() {
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk) = generate_recipient_keypair();
        let dev_a = DeviceId::new("A");
        let dev_b = DeviceId::new("B");

        let work_a = TempDir::new().unwrap();
        let work_b = TempDir::new().unwrap();
        std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
        std::fs::write(work_a.path().join("vim/f"), b"hello").unwrap();

        let mut ma = Manifest::new("A");
        let files_a = vec![mf(&work_a, "vim/f")];
        let ctx_a = SyncContext {
            device: &dev_a,
            files: &files_a,
            recip_keys: &pk,
            recip_secrets: &sk,
            resolver: None,
            now: SystemTime::UNIX_EPOCH,
        };
        sync(&store, &mut ma, &ctx_a).await.unwrap();

        let mut mb = Manifest::new("B");
        let files_b = vec![mf(&work_b, "vim/f")];
        let ctx_b = SyncContext {
            device: &dev_b,
            files: &files_b,
            recip_keys: &pk,
            recip_secrets: &sk,
            resolver: None,
            now: SystemTime::UNIX_EPOCH,
        };
        sync(&store, &mut mb, &ctx_b).await.unwrap();

        assert_eq!(
            std::fs::read(work_b.path().join("vim/f")).unwrap(),
            b"hello"
        );
        assert_eq!(ma.entries, mb.entries);
    }
}

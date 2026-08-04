//! The sync engine: pull remote manifest, diff, apply pulls/conflicts, push
//! new blobs and a conditionally-put manifest. Retries on CAS failure.

use crate::conflict::{resolve_conflict, ConflictResolver, Resolution};
use crate::diff::{diff, DiffOp};
use crate::local_io::{open_sealed, read_and_seal, seal_plaintext, write_plaintext};
use crate::SyncError;
use bytes::Bytes;
use cs_config::ConflictPolicy;
use cs_crypto::{RecipientKeys, RecipientSecrets};
use cs_manifest::{ConfigPath, DeviceId, Entry, Manifest};
use cs_storage::{Etag, RemoteStore};
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

async fn fetch_remote_manifest(
    store: &dyn RemoteStore,
) -> Result<(Manifest, Option<Etag>), SyncError> {
    // Get the etag from list (the store's own version, not the manifest's
    // internal version field).
    let etag = store
        .list("")
        .await?
        .into_iter()
        .find(|m| m.name == MANIFEST_KEY)
        .map(|m| m.etag);

    match store.get(MANIFEST_KEY).await {
        Ok(bytes) => {
            let m = Manifest::from_bytes(&bytes).map_err(|e| SyncError::Manifest(e.to_string()))?;
            Ok((m, etag))
        }
        Err(cs_storage::StorageError::NotFound(_)) => Ok((Manifest::new("remote"), None)),
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

    // Phase 0: scan local files into the manifest.
    let staged_pushes: Vec<PendingPush> = scan_local(local, inputs)?;

    // Upload all staged blobs ONCE in parallel (content-addressed + immutable).
    // Consume pushes by value to avoid cloning blob bytes.
    report.pushed.reserve(staged_pushes.len());
    let push_futures: Vec<_> = staged_pushes
        .into_iter()
        .map(|p| {
            let id_hex = p.entry.blob_id.to_hex();
            let hdr = blob_key(&id_hex);
            let body = blob_body_key(&id_hex);
            async move {
                store.put(&hdr, Bytes::from(p.header_blob), None).await?;
                store.put(&body, Bytes::from(p.body_blob), None).await?;
                Ok::<_, SyncError>((p.path, p.entry))
            }
        })
        .collect();
    let push_results = futures_util::future::try_join_all(push_futures).await?;
    for (path, entry) in push_results {
        local.entries.insert(path.clone(), entry);
        report.pushed.push(path);
    }

    // Build a quick lookup for managed files.
    let file_map: std::collections::HashMap<&cs_manifest::ConfigPath, &ManagedFile> =
        inputs.files.iter().map(|f| (&f.logical, f)).collect();

    // Phase 1: pull remote changes and resolve conflicts.
    let (remote_manifest, remote_etag) = fetch_remote_manifest(store).await?;
    let ops = diff(local, &remote_manifest);

    // Separate independent pull ops (can be parallelized) from sequential ops.
    let pull_ops: Vec<(&cs_manifest::ConfigPath, &Entry)> = ops
        .iter()
        .filter_map(|op| match op {
            DiffOp::PullLocal { path, remote } => Some((path, remote)),
            _ => None,
        })
        .collect();

    // Fetch all pull blobs in parallel.
    let pull_futures: Vec<_> = pull_ops
        .into_iter()
        .filter_map(|(path, remote)| {
            let mf = file_map.get(path)?;
            let id_hex = remote.blob_id.to_hex();
            let hdr_key = blob_key(&id_hex);
            let body_key = blob_body_key(&id_hex);
            Some(async move {
                let hdr = store.get(&hdr_key).await?;
                let body = store.get(&body_key).await?;
                Ok::<_, SyncError>((path, remote, mf, hdr, body))
            })
        })
        .collect();
    let pull_results = futures_util::future::try_join_all(pull_futures).await?;

    // Apply pull results sequentially (writes to disk + local manifest).
    for (path, remote, mf, hdr, body) in pull_results {
        let pt = open_sealed(&hdr, &body, path, remote, inputs.recip_secrets)?;
        write_plaintext(&mf.disk_path, &pt)?;
        local.entries.insert(path.clone(), remote.clone());
        report.pulled.push(path.clone());
    }

    // Process remaining ops (deletions, conflicts) sequentially.
    let mut conflict_pushes: Vec<cs_manifest::ConfigPath> = Vec::new();
    let mut aborted = false;

    for op in &ops {
        match op {
            DiffOp::PullLocal { .. } => { /* already handled above */ }
            DiffOp::PullDeletion { path, remote: _ } => {
                if let Some(mf) = file_map.get(path) {
                    let _ = std::fs::remove_file(&mf.disk_path);
                }
                local.entries.remove(path);
            }
            DiffOp::PushRemote { .. } | DiffOp::PushDeletion { .. } => {}
            DiffOp::InSync { .. } => {}
            DiffOp::Conflict {
                path,
                local: l,
                remote: r,
            } => {
                let mf = file_map
                    .get(path)
                    .ok_or_else(|| SyncError::Manifest(format!("no managed file for {path}")))?;
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
                            let id_hex = r.blob_id.to_hex();
                            let hdr = store.get(&blob_key(&id_hex)).await?;
                            let body = store.get(&blob_body_key(&id_hex)).await?;
                            let pt = open_sealed(&hdr, &body, path, r, inputs.recip_secrets)?;
                            write_plaintext(&mf.disk_path, &pt)?;
                            local.entries.insert(path.clone(), r.clone());
                            report.pulled.push(path.clone());
                        } else {
                            let mut clk = l.clock.clone();
                            clk.merge(&r.clock);
                            clk.bump(inputs.device);
                            let (entry, sf) = read_and_seal(
                                &mf.disk_path,
                                path,
                                l.aad_version + 1,
                                clk,
                                inputs.recip_keys,
                            )?;
                            // Upload conflict-push blobs immediately.
                            let cid_hex = entry.blob_id.to_hex();
                            store
                                .put(&blob_key(&cid_hex), Bytes::from(sf.header_blob), None)
                                .await?;
                            store
                                .put(&blob_body_key(&cid_hex), Bytes::from(sf.body_blob), None)
                                .await?;
                            local.entries.insert(path.clone(), entry);
                            conflict_pushes.push(path.clone());
                        }
                        report.conflicts_resolved.push(path.clone());
                    }
                }
            }
        }
    }

    if aborted {
        return Ok(report);
    }

    // staged_pushes already consumed during upload above; add conflict pushes.
    report.pushed.extend(conflict_pushes);

    // Phase 2: manifest CAS retry loop (only retries the manifest put,
    // not blob uploads — blobs are already content-addressed on the store).
    local.clock.bump(inputs.device);
    local.manifest_version += 1;
    local.device_id = inputs.device.as_str().to_string();

    for attempt in 0..MAX_CAS_RETRIES {
        let current_etag = if attempt == 0 {
            remote_etag.clone()
        } else {
            // Re-fetch remote to detect concurrent changes before our put.
            let (remote, etag) = fetch_remote_manifest(store).await?;
            for (path, entry) in &remote.entries {
                if !local.entries.contains_key(path) {
                    local.entries.insert(path.clone(), entry.clone());
                }
            }
            etag
        };

        let bytes = local
            .to_bytes()
            .map_err(|e| SyncError::Manifest(e.to_string()))?;

        match store
            .put(MANIFEST_KEY, Bytes::from(bytes), current_etag.as_ref())
            .await
        {
            Ok(_etag) => return Ok(report),
            Err(cs_storage::StorageError::PreconditionFailed) if attempt + 1 < MAX_CAS_RETRIES => {
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
        // Distinguish NotFound (genuine deletion → tombstone) from other IO
        // errors (transient failures → propagate, don't tombstone).
        let on_disk = match std::fs::read(&mf.disk_path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(SyncError::Io(e)),
        };
        let mtime = match std::fs::metadata(&mf.disk_path) {
            Ok(m) => m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::time::SystemTime::UNIX_EPOCH,
            Err(e) => return Err(SyncError::Io(e)),
        };
        let existing = local.entries.get(&mf.logical).cloned();
        match (on_disk, existing) {
            (Some(plain), Some(prev)) => {
                let disk_hash = cs_manifest::Sha256::of(&plain);
                if disk_hash == prev.content_hash && !prev.deleted {
                    continue;
                }
                let mut clk = prev.clock.clone();
                clk.bump(inputs.device);
                // Use seal_plaintext to avoid re-reading the file from disk.
                let (entry, sf) = seal_plaintext(
                    &plain,
                    &mf.logical,
                    prev.aad_version + 1,
                    clk,
                    inputs.recip_keys,
                    mtime,
                )?;
                local.entries.insert(mf.logical.clone(), entry.clone());
                staged.push(PendingPush {
                    path: mf.logical.clone(),
                    entry,
                    header_blob: sf.header_blob,
                    body_blob: sf.body_blob,
                });
            }
            (Some(plain), None) => {
                let mut clk = local.clock.clone();
                clk.bump(inputs.device);
                let aad_version = 1;
                let (mut entry, sf) = seal_plaintext(
                    &plain,
                    &mf.logical,
                    aad_version,
                    clk,
                    inputs.recip_keys,
                    mtime,
                )?;
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
                let mut t = prev.clone();
                t.deleted = true;
                t.clock.bump(inputs.device);
                local.entries.insert(mf.logical.clone(), t);
            }
            (None, _) => {}
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

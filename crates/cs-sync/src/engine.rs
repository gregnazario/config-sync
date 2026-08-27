//! The sync engine: pull remote manifest, diff, apply pulls/conflicts, push
//! new blobs and a conditionally-put manifest. Retries on CAS failure.

use crate::conflict::{resolve_conflict, Conflict, ConflictResolver, Resolution};
use crate::diff::{diff, DiffOp};
use crate::local_io::{
    open_manifest, open_sealed, read_and_seal, seal_manifest, seal_plaintext, write_plaintext,
};
use crate::SyncError;
use bytes::Bytes;
use cs_config::ConflictPolicy;
use cs_crypto::{RecipientKeys, RecipientSecrets};
use cs_manifest::{ConfigPath, DeviceId, Entry, Manifest, Sha256};
use cs_storage::{Etag, RemoteStore};
use std::path::PathBuf;
use std::time::SystemTime;

const MANIFEST_KEY: &str = "manifest.json";
const BLOB_PREFIX: &str = "blobs/";
const MAX_CAS_RETRIES: u32 = 3;

/// Upper bound on the sealed manifest object read from a store. Synced config
/// inventories are tiny; anything larger signals a hostile or broken store.
const MAX_MANIFEST_OBJECT_BYTES: usize = 64 * 1024 * 1024;
/// Upper bound on a single blob (header or body). Headers are ~1.2 KiB and
/// bodies are file-sized; the cap exists to stop a hostile store from
/// buffering an unbounded "blob" into memory.
const MAX_BLOB_BYTES: usize = 256 * 1024 * 1024;

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
    /// Manifest signing key derived from the vault's RIK. Signs every pushed
    /// manifest and verifies every fetched one.
    pub manifest_signer: &'a cs_crypto::ManifestSigningKey,
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
    recip_secrets: &RecipientSecrets,
    manifest_signer: &cs_crypto::ManifestSigningKey,
    local_version: u64,
    has_local_anchor: bool,
    now: SystemTime,
) -> Result<(Manifest, Option<Etag>, bool), SyncError> {
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
            if bytes.len() > MAX_MANIFEST_OBJECT_BYTES {
                return Err(SyncError::Manifest(format!(
                    "remote manifest is {} bytes (cap {MAX_MANIFEST_OBJECT_BYTES}); refusing to read",
                    bytes.len()
                )));
            }
            // We hold manifest bytes but the listing has no ETag: the store is
            // inconsistent or hostile. Refuse rather than risk an unconditional
            // put clobbering concurrent state.
            let Some(etag) = etag else {
                return Err(SyncError::Manifest(
                    "store served a manifest but its listing has no ETag for it; refusing to sync"
                        .into(),
                ));
            };
            // The manifest is authenticated twice over: an Ed25519 signature
            // under the RIK-derived key (checked first, covers the version and
            // seal time carried outside the ciphertext) and the AEAD envelope
            // under the vault's recipient keys. A store that cannot produce
            // both (forgery, wrong vault, stale replay, legacy plaintext)
            // fails closed here — before any entry is allowed to trigger a
            // pull, deletion, or conflict.
            let m = open_manifest(
                &bytes,
                recip_secrets,
                &manifest_signer.verifying_key_bytes(),
                has_local_anchor,
                now,
            )?;
            if m.manifest_version < local_version {
                return Err(SyncError::Manifest(format!(
                    "remote manifest (v{}) is older than the last one seen locally (v{}): \
                     possible rollback. If the store was deliberately reset, remove the local \
                     manifest cache and sync again",
                    m.manifest_version, local_version
                )));
            }
            Ok((m, Some(etag), true))
        }
        Err(cs_storage::StorageError::NotFound(_)) => Ok((Manifest::new("remote"), None, false)),
        Err(e) => Err(e.into()),
    }
}

/// Merge remote entries for paths this device does not manage into the
/// *outgoing* manifest, so a push never erases other devices' entries
/// (losing their updates, or resurrecting files they deleted).
///
/// The merge happens on a copy at push time, NOT on the local manifest: a
/// device that adopts an unmanaged entry into its own state would later treat
/// that path as already synced and never fetch the content when it starts
/// managing it.
fn merge_unmanaged_entries(
    outgoing: &mut Manifest,
    remote: &Manifest,
    file_map: &std::collections::HashMap<&ConfigPath, &ManagedFile>,
    now: SystemTime,
) {
    // Preserve other devices' conflict-resolution records (the newer record
    // per path wins; nothing reads them yet, but they carry GC hints).
    for (path, r) in &remote.resolutions {
        if outgoing
            .resolutions
            .get(path)
            .map(|o| o.at_version < r.at_version)
            .unwrap_or(true)
        {
            outgoing.resolutions.insert(path.clone(), r.clone());
        }
    }
    for (path, r) in &remote.entries {
        if file_map.contains_key(path) {
            // Managed here: this device's (freshly synced) state is authoritative.
            continue;
        }
        match outgoing.entries.get(path) {
            None => {
                // Unknown here (never managed, or deleted from our config):
                // preserve the remote state verbatim.
                outgoing.entries.insert(path.clone(), r.clone());
            }
            Some(l) => {
                // Previously known but no longer managed: converge to the
                // causally-newer entry with the deterministic tie-break, the
                // same rule the engine uses for managed conflicts.
                let conflict = Conflict {
                    path: path.clone(),
                    local: l.clone(),
                    remote: r.clone(),
                };
                if let Ok(Resolution::Resolved { chosen, .. }) = resolve_conflict(
                    &conflict,
                    ConflictPolicy::LatestWins,
                    None,
                    outgoing.manifest_version,
                    now,
                ) {
                    if chosen.blob_id == r.blob_id && chosen.deleted == r.deleted {
                        outgoing.entries.insert(path.clone(), r.clone());
                    }
                }
            }
        }
    }
}

/// Authenticate a fetched header+body pair against the manifest entry and
/// decrypt it. Verifies the content-addressed blob id, the plaintext content
/// hash, and the declared size — a hostile store cannot substitute or replay
/// blobs past these checks.
fn authenticate_and_open(
    hdr: &[u8],
    body: &[u8],
    path: &ConfigPath,
    remote: &Entry,
    secrets: &RecipientSecrets,
) -> Result<Vec<u8>, SyncError> {
    if hdr.len() > MAX_BLOB_BYTES || body.len() > MAX_BLOB_BYTES {
        return Err(SyncError::Manifest(format!(
            "blob for {path} exceeds size cap; refusing"
        )));
    }
    if Sha256::of(hdr) != remote.blob_id {
        return Err(SyncError::Manifest(format!(
            "header blob for {path} does not match its manifest blob id; \
             store is corrupt or hostile"
        )));
    }
    let pt = open_sealed(hdr, body, path, remote, secrets)?;
    if pt.len() as u64 != remote.size || Sha256::of(&pt) != remote.content_hash {
        return Err(SyncError::Manifest(format!(
            "decrypted content for {path} does not match its manifest content hash; \
             store is corrupt or hostile"
        )));
    }
    Ok(pt)
}

/// Authenticate, decrypt, and apply one remote entry: write the plaintext to
/// `target` and record the entry in the local manifest.
fn verify_and_write(
    hdr: &[u8],
    body: &[u8],
    path: &ConfigPath,
    remote: &Entry,
    target: &std::path::Path,
    secrets: &RecipientSecrets,
    local: &mut Manifest,
) -> Result<(), SyncError> {
    let pt = authenticate_and_open(hdr, body, path, remote, secrets)?;
    write_plaintext(target, &pt)?;
    local.entries.insert(path.clone(), remote.clone());
    Ok(())
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

    // Whether this device carries trusted sync history. Must be captured
    // BEFORE scan_local seeds entries: a fresh device staging its first push
    // is not "history". Version > 0 or pre-existing entries both imply a
    // prior successful sync.
    let had_local_history = local.manifest_version > 0 || !local.entries.is_empty();

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
    let pre_bump_version = local.manifest_version;
    let (remote_manifest, remote_etag, remote_present) = fetch_remote_manifest(
        store,
        inputs.recip_secrets,
        inputs.manifest_signer,
        pre_bump_version,
        had_local_history,
        inputs.now,
    )
    .await?;
    if !remote_present && had_local_history {
        // The local cache references history the store knows nothing about:
        // either this is another vault's store or the store was reset.
        // Pushing would seed entries whose blobs were never uploaded.
        return Err(SyncError::Manifest(
            "the store has no manifest but the local cache has sync history; \\
             if the store was deliberately reset, remove the local manifest cache \\
             before syncing again, otherwise check the store path"
                .into(),
        ));
    }
    let ops = diff(local, &remote_manifest);
    // Remote state for unmanaged paths is merged into the *outgoing*
    // manifest at push time (see merge_unmanaged_entries).
    let mut merge_remote = remote_manifest.clone();

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

    // Apply pull results sequentially (writes to disk + local manifest). Each
    // entry is authenticated against its manifest blob id and content hash
    // before it is allowed near the filesystem.
    for (path, remote, mf, hdr, body) in pull_results {
        verify_and_write(
            &hdr,
            &body,
            path,
            remote,
            &mf.disk_path,
            inputs.recip_secrets,
            local,
        )?;
        report.pulled.push(path.clone());
    }

    // Process remaining ops (deletions, conflicts) sequentially.
    let mut conflict_pushes: Vec<cs_manifest::ConfigPath> = Vec::new();
    let mut aborted = false;

    for op in &ops {
        match op {
            DiffOp::PullLocal { .. } => { /* already handled above */ }
            DiffOp::PullDeletion { path, remote } => {
                // Unmanaged paths are handled by the push-time merge.
                let Some(mf) = file_map.get(path) else {
                    continue;
                };
                let _ = std::fs::remove_file(&mf.disk_path);
                // Keep the tombstone entry so every device converges to
                // "deleted" instead of resurrecting the file on a later push.
                local.entries.insert(path.clone(), remote.clone());
            }
            DiffOp::PushRemote { .. } | DiffOp::PushDeletion { .. } => {}
            DiffOp::InSync { .. } => {}
            DiffOp::Conflict {
                path,
                local: l,
                remote: r,
            } => {
                // Unmanaged conflicts were converged in adopt_unmanaged_paths.
                let Some(mf) = file_map.get(path) else {
                    continue;
                };
                let conflict = Conflict {
                    path: path.clone(),
                    local: l.clone(),
                    remote: r.clone(),
                };
                let res = resolve_conflict(
                    &conflict,
                    mf.policy,
                    inputs.resolver,
                    local.manifest_version.saturating_add(1),
                    inputs.now,
                )?;
                let res_for_record = res.clone();
                match res {
                    Resolution::Aborted => {
                        aborted = true;
                        report.aborted = true;
                        break;
                    }
                    Resolution::Resolved { chosen, .. } => {
                        // A tombstone winner is a DELETION, not content: never
                        // fetch the tombstone's (stale) blob and never try to
                        // re-seal from a file that no longer exists. Apply the
                        // deletion exactly like PullDeletion would.
                        if chosen.deleted {
                            let _ = std::fs::remove_file(&mf.disk_path);
                            let mut clk = l.clock.clone();
                            clk.merge(&r.clock);
                            clk.bump(inputs.device);
                            let mut t = chosen.clone();
                            t.clock = clk;
                            local.entries.insert(path.clone(), t.clone());
                            report.conflicts_resolved.push(path.clone());
                            if let Some(record) = crate::conflict::make_record(
                                &res_for_record,
                                local.manifest_version,
                            ) {
                                local.resolutions.insert(path.clone(), record);
                            }
                            conflict_pushes.push(path.clone());
                            continue;
                        }
                        if chosen.blob_id == r.blob_id {
                            let id_hex = r.blob_id.to_hex();
                            let hdr = store.get(&blob_key(&id_hex)).await?;
                            let body = store.get(&blob_body_key(&id_hex)).await?;
                            verify_and_write(
                                &hdr,
                                &body,
                                path,
                                r,
                                &mf.disk_path,
                                inputs.recip_secrets,
                                local,
                            )?;
                            report.pulled.push(path.clone());
                        } else {
                            // Chosen is local. If the policy was Manual (KeepBoth),
                            // also fetch and write the remote version as a .remote
                            // sidecar so the user can review/merge manually.
                            if mf.policy == ConflictPolicy::Manual {
                                let id_hex = r.blob_id.to_hex();
                                let hdr = store.get(&blob_key(&id_hex)).await?;
                                let body = store.get(&blob_body_key(&id_hex)).await?;
                                let remote_pt = authenticate_and_open(
                                    &hdr,
                                    &body,
                                    path,
                                    r,
                                    inputs.recip_secrets,
                                )?;
                                let remote_path = {
                                    let mut p = mf.disk_path.clone();
                                    let ext = p
                                        .extension()
                                        .map(|e| {
                                            let mut s = e.to_string_lossy().into_owned();
                                            s.push_str(".remote");
                                            s
                                        })
                                        .unwrap_or_else(|| "remote".to_string());
                                    p.set_extension(ext);
                                    p
                                };
                                write_plaintext(&remote_path, &remote_pt)?;
                            }

                            let mut clk = l.clock.clone();
                            clk.merge(&r.clock);
                            clk.bump(inputs.device);
                            let (entry, sf) = read_and_seal(
                                &mf.disk_path,
                                path,
                                l.aad_version.saturating_add(1),
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
                        // Record the resolution so other devices converge.
                        if let Some(record) =
                            crate::conflict::make_record(&res_for_record, local.manifest_version)
                        {
                            local.resolutions.insert(path.clone(), record);
                        }
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
    // Merge the remote's aggregate clock so entries this device creates
    // later start from a clock that dominates everything it has seen.
    local.clock.merge(&merge_remote.clock);
    local.device_id = inputs.device.as_str().to_string();

    for attempt in 0..MAX_CAS_RETRIES {
        let current_etag = if attempt == 0 {
            remote_etag.clone()
        } else {
            // Re-fetch remote and re-diff to detect concurrent changes to
            // existing paths. Apply pulls/deletions fully (fetch blobs, write
            // to disk) so the local state matches the manifest we're about to
            // push. Failures propagate: adopting a remote entry whose blob
            // can't be fetched/decrypted would silently resurrect stale local
            // content as the winner.
            let (remote, etag, present) = fetch_remote_manifest(
                store,
                inputs.recip_secrets,
                inputs.manifest_signer,
                pre_bump_version,
                had_local_history,
                inputs.now,
            )
            .await?;
            if !present {
                // The manifest vanished mid-sync (deliberate reset or a
                // hostile store): never push history-derived state over it.
                return Err(SyncError::Manifest(
                    "the remote manifest disappeared during the sync; retry".into(),
                ));
            }
            merge_remote = remote.clone();
            let retry_ops = diff(local, &remote);
            for op in &retry_ops {
                match op {
                    DiffOp::PullLocal { path, remote } => {
                        let Some(mf) = file_map.get(path) else {
                            continue;
                        };
                        let id_hex = remote.blob_id.to_hex();
                        let hdr = store.get(&blob_key(&id_hex)).await?;
                        let body = store.get(&blob_body_key(&id_hex)).await?;
                        verify_and_write(
                            &hdr,
                            &body,
                            path,
                            remote,
                            &mf.disk_path,
                            inputs.recip_secrets,
                            local,
                        )?;
                    }
                    DiffOp::PullDeletion { path, remote } => {
                        let Some(mf) = file_map.get(path) else {
                            continue;
                        };
                        let _ = std::fs::remove_file(&mf.disk_path);
                        // Keep the tombstone (see the main ops loop).
                        local.entries.insert(path.clone(), remote.clone());
                    }
                    DiffOp::InSync { .. }
                    | DiffOp::PushRemote { .. }
                    | DiffOp::PushDeletion { .. }
                    | DiffOp::Conflict { .. } => {
                        // Our local is ahead or in sync; keep our version.
                    }
                }
            }
            etag
        };

        // The manifest is pushed as a sealed, authenticated envelope: the
        // store cannot read it, and (combined with the version check on
        // fetch) cannot forge or roll it back undetected.
        // The pushed manifest is local state plus remote entries for paths
        // this device doesn't manage (so their updates and tombstones are
        // never erased by a subset device's push).
        let mut outgoing = local.clone();
        merge_unmanaged_entries(&mut outgoing, &merge_remote, &file_map, inputs.now);
        // CRITICAL versioning invariant: the pushed version must exceed BOTH
        // our local version and every remote version seen this run — bumping
        // from the local value alone would let a device that was offline (or
        // freshly reset) push a LOWER version with the current ETag,
        // regressing the store fleet-wide and tripping every ahead device's
        // rollback protection.
        outgoing.manifest_version = local
            .manifest_version
            .max(merge_remote.manifest_version)
            .saturating_add(1);
        let sealed = seal_manifest(
            &outgoing,
            inputs.recip_keys,
            inputs.manifest_signer,
            inputs.now,
        )?;
        // An absent remote manifest means "must be absent" — the put itself is
        // conditional so a concurrent first-writer can never be silently
        // overwritten by an unconditional PUT.
        let cas_guard = current_etag.clone().or_else(|| Some(Etag(String::new())));

        match store
            .put(MANIFEST_KEY, Bytes::from(sealed), cas_guard.as_ref())
            .await
        {
            Ok(_etag) => {
                // Keep the local cache in step with what was actually pushed.
                local.manifest_version = outgoing.manifest_version;
                return Ok(report);
            }
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
        // Read metadata first, then content, to minimize the TOCTOU window
        // between bytes and mtime.
        let (on_disk, mtime) = match std::fs::metadata(&mf.disk_path) {
            Ok(meta) => {
                let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                match std::fs::read(&mf.disk_path) {
                    Ok(b) => (Some(b), modified),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        (None, std::time::SystemTime::UNIX_EPOCH)
                    }
                    Err(e) => return Err(SyncError::Io(e)),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (None, std::time::SystemTime::UNIX_EPOCH)
            }
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
                    prev.aad_version.saturating_add(1),
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
                let (entry, sf) = seal_plaintext(
                    &plain,
                    &mf.logical,
                    aad_version,
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
    use cs_crypto::{generate_rik, ManifestSigningKey};
    use cs_storage::LocalFs;
    use tempfile::TempDir;

    /// A vault fixture: RIK + derived recipient keys + manifest signer.
    fn vault() -> (
        cs_crypto::RecipientKeys,
        cs_crypto::RecipientSecrets,
        ManifestSigningKey,
    ) {
        let rik = generate_rik().unwrap();
        let (pk, sk) = cs_crypto::derive_recipient_keypair(&rik);
        (pk, sk, ManifestSigningKey::derive_from_rik(&rik))
    }

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
        let (pk, sk, signer) = vault();
        let dev_a = DeviceId::new("A");
        let dev_b = DeviceId::new("B");

        let work_a = TempDir::new().unwrap();
        let work_b = TempDir::new().unwrap();
        std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
        std::fs::write(work_a.path().join("vim/f"), b"hello").unwrap();

        let mut ma = Manifest::new("A");
        let files_a = vec![mf(&work_a, "vim/f")];
        let ctx_a = ctx(&dev_a, &files_a, &pk, &sk, &signer);
        sync(&store, &mut ma, &ctx_a).await.unwrap();

        let mut mb = Manifest::new("B");
        let files_b = vec![mf(&work_b, "vim/f")];
        let ctx_b = ctx(&dev_b, &files_b, &pk, &sk, &signer);
        sync(&store, &mut mb, &ctx_b).await.unwrap();

        assert_eq!(
            std::fs::read(work_b.path().join("vim/f")).unwrap(),
            b"hello"
        );
        assert_eq!(ma.entries, mb.entries);
    }

    fn ctx<'a>(
        dev: &'a DeviceId,
        files: &'a [ManagedFile],
        pk: &'a cs_crypto::RecipientKeys,
        sk: &'a cs_crypto::RecipientSecrets,
        signer: &'a ManifestSigningKey,
    ) -> SyncContext<'a> {
        SyncContext {
            device: dev,
            files,
            recip_keys: pk,
            recip_secrets: sk,
            manifest_signer: signer,
            resolver: None,
            now: SystemTime::UNIX_EPOCH,
        }
    }

    #[tokio::test]
    async fn remote_manifest_is_encrypted_and_tamper_evident() {
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev_a = DeviceId::new("A");

        let work = TempDir::new().unwrap();
        std::fs::create_dir_all(work.path().join("vim")).unwrap();
        std::fs::write(work.path().join("vim/f"), b"secret-path-name").unwrap();
        let files = vec![mf(&work, "vim/f")];
        let mut m = Manifest::new("A");
        sync(&store, &mut m, &ctx(&dev_a, &files, &pk, &sk, &signer))
            .await
            .unwrap();

        // The store must never see the synced file inventory in the clear.
        let raw = std::fs::read(shared.path().join("manifest.json")).unwrap();
        assert!(
            !raw.windows(5).any(|w| w == b"vim/f"),
            "logical paths must not appear in the stored manifest"
        );
        assert!(
            !raw.windows(6).any(|w| w == b"secret"),
            "manifest must be stored as ciphertext"
        );

        // A single flipped bit anywhere in the sealed manifest must make the
        // next sync fail closed instead of trusting the content.
        for i in [0, 10, raw.len() / 2, raw.len() - 1] {
            let mut tampered = raw.clone();
            tampered[i] ^= 0xff;
            std::fs::write(shared.path().join("manifest.json"), &tampered).unwrap();
            let mut m2 = Manifest::new("B");
            let r = sync(&store, &mut m2, &ctx(&dev_a, &files, &pk, &sk, &signer)).await;
            assert!(r.is_err(), "tampered manifest at byte {i} must fail closed");
        }
        // Restore; sync works again.
        std::fs::write(shared.path().join("manifest.json"), &raw).unwrap();
        let mut m3 = Manifest::new("C");
        sync(&store, &mut m3, &ctx(&dev_a, &files, &pk, &sk, &signer))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn wrong_identity_cannot_read_or_supplant_manifest() {
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let (other_pk, other_sk, _other_signer) = vault();
        let dev = DeviceId::new("A");

        let work = TempDir::new().unwrap();
        std::fs::create_dir_all(work.path().join("vim")).unwrap();
        std::fs::write(work.path().join("vim/f"), b"x").unwrap();
        let files = vec![mf(&work, "vim/f")];
        let mut m = Manifest::new("A");
        sync(&store, &mut m, &ctx(&dev, &files, &pk, &sk, &signer))
            .await
            .unwrap();

        // A different identity cannot decrypt the manifest.
        let mut outsider = Manifest::new("Eve");
        let r = sync(
            &store,
            &mut outsider,
            &ctx(&dev, &files, &other_pk, &other_sk, &signer),
        )
        .await;
        assert!(r.is_err(), "wrong identity must not read the manifest");
    }

    #[tokio::test]
    async fn rolled_back_manifest_is_rejected() {
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev = DeviceId::new("A");

        let work = TempDir::new().unwrap();
        std::fs::create_dir_all(work.path().join("vim")).unwrap();
        std::fs::write(work.path().join("vim/f"), b"v1").unwrap();
        let files = vec![mf(&work, "vim/f")];
        let mut m = Manifest::new("A");
        sync(&store, &mut m, &ctx(&dev, &files, &pk, &sk, &signer))
            .await
            .unwrap();
        let v1_sealed = std::fs::read(shared.path().join("manifest.json")).unwrap();

        std::fs::write(work.path().join("vim/f"), b"v2").unwrap();
        sync(&store, &mut m, &ctx(&dev, &files, &pk, &sk, &signer))
            .await
            .unwrap();

        // A hostile store replays the v1 manifest. The device that has seen
        // v2 must refuse instead of silently accepting rolled-back state.
        std::fs::write(shared.path().join("manifest.json"), &v1_sealed).unwrap();
        let r = sync(&store, &mut m, &ctx(&dev, &files, &pk, &sk, &signer)).await;
        assert!(
            matches!(r, Err(SyncError::Manifest(_))),
            "rollback must be rejected, got {r:?}"
        );
    }

    #[tokio::test]
    async fn behind_device_does_not_regress_the_manifest_version() {
        // B was offline while A kept syncing. B's push must not regress the
        // fleet-wide manifest_version (which would brick A with a spurious
        // rollback error).
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev_a = DeviceId::new("A");
        let dev_b = DeviceId::new("B");

        let work_a = TempDir::new().unwrap();
        std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
        std::fs::write(work_a.path().join("vim/f"), b"v1").unwrap();
        let files_a = vec![mf(&work_a, "vim/f")];
        let work_b = TempDir::new().unwrap();
        let files_b = vec![mf(&work_b, "vim/f")];
        let mut ma = Manifest::new("A");
        let mut mb = Manifest::new("B");
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        sync(&store, &mut mb, &ctx(&dev_b, &files_b, &pk, &sk, &signer))
            .await
            .unwrap(); // both at v1

        // A advances alone, twice.
        std::fs::write(work_a.path().join("vim/f"), b"v2").unwrap();
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        std::fs::write(work_a.path().join("vim/f"), b"v3").unwrap();
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        let high_water = ma.manifest_version;
        assert!(mb.manifest_version < high_water, "B must be behind");

        // B (behind) syncs. Its push must exceed the remote version it saw,
        // not regress the store to B's local version + 1.
        std::fs::write(work_b.path().join("vim/f"), b"b-edit").unwrap();
        sync(&store, &mut mb, &ctx(&dev_b, &files_b, &pk, &sk, &signer))
            .await
            .unwrap();
        assert!(
            mb.manifest_version > high_water,
            "pushed version must exceed the remote high-water mark {}, got {}",
            high_water,
            mb.manifest_version
        );

        // And A — now behind — must sync cleanly (pre-fix this was a
        // permanent spurious "possible rollback" failure).
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        assert!(ma.manifest_version > high_water);
    }

    #[tokio::test]
    async fn idle_vault_syncs_after_long_gap() {
        // A vault untouched for more than the freshness window must remain
        // syncable for a device with local history (staleness only bounds
        // anchorless devices).
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev = DeviceId::new("A");
        let t0 = SystemTime::UNIX_EPOCH;
        let t_weeks_later = t0 + std::time::Duration::from_secs(30 * 24 * 60 * 60);

        let work = TempDir::new().unwrap();
        std::fs::create_dir_all(work.path().join("vim")).unwrap();
        std::fs::write(work.path().join("vim/f"), b"old").unwrap();
        let files = vec![mf(&work, "vim/f")];
        let mut m = Manifest::new("A");
        let ctx_t0 = SyncContext {
            device: &dev,
            files: &files,
            recip_keys: &pk,
            recip_secrets: &sk,
            manifest_signer: &signer,
            resolver: None,
            now: t0,
        };
        sync(&store, &mut m, &ctx_t0).await.unwrap();

        let ctx_later = SyncContext {
            device: &dev,
            files: &files,
            recip_keys: &pk,
            recip_secrets: &sk,
            manifest_signer: &signer,
            resolver: None,
            now: t_weeks_later,
        };
        sync(&store, &mut m, &ctx_later)
            .await
            .expect("a device with local history must accept an idle vault's manifest");
    }

    #[tokio::test]
    async fn delete_vs_edit_conflict_converges_both_ways() {
        // A deletes; B concurrently edits. Whichever side wins, the sync must
        // not error, must not resurrect content from the tombstone's blob,
        // and both devices must converge.
        async fn run(choice: crate::ConflictChoice) -> (bool, bool) {
            let shared = TempDir::new().unwrap();
            let store = LocalFs::new(shared.path());
            let (pk, sk, signer) = vault();
            let dev_a = DeviceId::new("A");
            let dev_b = DeviceId::new("B");

            let work_a = TempDir::new().unwrap();
            let work_b = TempDir::new().unwrap();
            std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
            std::fs::write(work_a.path().join("vim/f"), b"base").unwrap();
            let files_a = vec![ManagedFile {
                logical: ConfigPath::new("vim/f"),
                disk_path: work_a.path().join("vim/f"),
                policy: ConflictPolicy::Prompt,
            }];
            let files_b: Vec<ManagedFile> = files_a
                .iter()
                .map(|f| ManagedFile {
                    logical: f.logical.clone(),
                    disk_path: work_b.path().join("vim/f"),
                    policy: ConflictPolicy::Prompt,
                })
                .collect();
            let mut ma = Manifest::new("A");
            let mut mb = Manifest::new("B");
            let resolver = crate::FixedResolver(choice);
            let ctx_a = SyncContext {
                device: &dev_a,
                files: &files_a,
                recip_keys: &pk,
                recip_secrets: &sk,
                manifest_signer: &signer,
                resolver: Some(&resolver),
                now: SystemTime::UNIX_EPOCH,
            };
            let ctx_b = SyncContext {
                device: &dev_b,
                files: &files_b,
                recip_keys: &pk,
                recip_secrets: &sk,
                manifest_signer: &signer,
                resolver: Some(&resolver),
                now: SystemTime::UNIX_EPOCH,
            };
            sync(&store, &mut ma, &ctx_a).await.unwrap();
            sync(&store, &mut mb, &ctx_b).await.unwrap();

            // A deletes; B edits — concurrently.
            std::fs::remove_file(work_a.path().join("vim/f")).unwrap();
            std::fs::write(work_b.path().join("vim/f"), b"b-edit").unwrap();
            sync(&store, &mut ma, &ctx_a).await.unwrap();
            sync(&store, &mut mb, &ctx_b)
                .await
                .expect("delete-vs-edit resolution must not error");

            // Settle: both sync twice.
            sync(&store, &mut ma, &ctx_a).await.unwrap();
            sync(&store, &mut mb, &ctx_b).await.unwrap();
            sync(&store, &mut ma, &ctx_a).await.unwrap();
            let file_a = work_a.path().join("vim/f").exists();
            let file_b = work_b.path().join("vim/f").exists();
            (file_a, file_b)
        }

        // KeepRemote (the tombstone wins): both devices converge to deleted.
        let (a, b) = run(crate::ConflictChoice::KeepRemote).await;
        assert!(!a && !b, "tombstone must win cleanly: a={a} b={b}");

        // KeepLocal (B's edit wins): both devices converge to the live edit.
        let (a, b) = run(crate::ConflictChoice::KeepLocal).await;
        assert!(a && b, "live edit must win cleanly: a={a} b={b}");
    }

    #[tokio::test]
    async fn fresh_device_rejects_stale_replayed_manifest() {
        // A device with no prior history cannot use the monotonic version
        // check; the signed seal-time freshness window is what protects it.
        // A manifest genuinely sealed more than MAX_MANIFEST_AGE_SECS ago
        // (here: a hostile replay of an old frame) must be rejected.
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev_a = DeviceId::new("A");
        let t0 = SystemTime::UNIX_EPOCH;

        let work = TempDir::new().unwrap();
        std::fs::create_dir_all(work.path().join("vim")).unwrap();
        std::fs::write(work.path().join("vim/f"), b"v1").unwrap();
        let files = vec![mf(&work, "vim/f")];
        let mut ma = Manifest::new("A");
        let ctx_t0 = SyncContext {
            device: &dev_a,
            files: &files,
            recip_keys: &pk,
            recip_secrets: &sk,
            manifest_signer: &signer,
            resolver: None,
            now: t0,
        };
        sync(&store, &mut ma, &ctx_t0).await.unwrap();
        let old_frame = std::fs::read(shared.path().join("manifest.json")).unwrap();

        // Eight days later the hostile store replays the day-0 frame to a
        // brand-new device. The signature and AEAD are perfectly valid —
        // only the freshness window can catch it.
        std::fs::write(shared.path().join("manifest.json"), &old_frame).unwrap();
        let t8 = t0 + std::time::Duration::from_secs(8 * 24 * 60 * 60);
        let dev_c = DeviceId::new("C");
        let work_c = TempDir::new().unwrap();
        let files_c = vec![mf(&work_c, "vim/f")];
        let mut mc = Manifest::new("C");
        let ctx_t8 = SyncContext {
            device: &dev_c,
            files: &files_c,
            recip_keys: &pk,
            recip_secrets: &sk,
            manifest_signer: &signer,
            resolver: None,
            now: t8,
        };
        let r = sync(&store, &mut mc, &ctx_t8).await;
        assert!(
            matches!(r, Err(SyncError::Manifest(_))),
            "stale replay to a fresh device must be rejected, got {r:?}"
        );
        assert!(
            !work_c.path().join("vim/f").exists(),
            "nothing may be written from a stale manifest"
        );
    }

    #[tokio::test]
    async fn tombstones_are_retained_and_do_not_resurrect() {
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev_a = DeviceId::new("A");
        let dev_b = DeviceId::new("B");
        let dev_c = DeviceId::new("C");

        let work_a = TempDir::new().unwrap();
        let work_b = TempDir::new().unwrap();
        let work_c = TempDir::new().unwrap();
        std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
        std::fs::write(work_a.path().join("vim/f"), b"doomed").unwrap();

        let files_a = vec![mf(&work_a, "vim/f")];
        let files_b = vec![mf(&work_b, "vim/f")];
        let files_c = vec![mf(&work_c, "vim/f")];

        let mut ma = Manifest::new("A");
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        let mut mb = Manifest::new("B");
        sync(&store, &mut mb, &ctx(&dev_b, &files_b, &pk, &sk, &signer))
            .await
            .unwrap();
        assert!(work_b.path().join("vim/f").exists());

        // A deletes the file; the tombstone must propagate and *stick*.
        std::fs::remove_file(work_a.path().join("vim/f")).unwrap();
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        sync(&store, &mut mb, &ctx(&dev_b, &files_b, &pk, &sk, &signer))
            .await
            .unwrap();
        assert!(!work_b.path().join("vim/f").exists(), "B must delete");

        // B (which adopted the tombstone) pushes its own manifest; then A
        // syncs again. Neither may resurrect the file.
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();
        assert!(
            ma.entries.get(&ConfigPath::new("vim/f")).map(|e| e.deleted) == Some(true),
            "tombstone must survive B's push"
        );

        // A brand-new device must never see the deleted file come back.
        let mut mc = Manifest::new("C");
        sync(&store, &mut mc, &ctx(&dev_c, &files_c, &pk, &sk, &signer))
            .await
            .unwrap();
        assert!(
            !work_c.path().join("vim/f").exists(),
            "fresh device must not resurrect the deleted file"
        );
        assert!(mc.entries.get(&ConfigPath::new("vim/f")).map(|e| e.deleted) == Some(true));
    }

    #[tokio::test]
    async fn unmanaged_remote_entries_survive_a_subset_device_push() {
        let shared = TempDir::new().unwrap();
        let store = LocalFs::new(shared.path());
        let (pk, sk, signer) = vault();
        let dev_a = DeviceId::new("A");
        let dev_b = DeviceId::new("B");

        // A manages and pushes vim/f.
        let work_a = TempDir::new().unwrap();
        std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
        std::fs::write(work_a.path().join("vim/f"), b"from-a").unwrap();
        let files_a = vec![mf(&work_a, "vim/f")];
        let mut ma = Manifest::new("A");
        sync(&store, &mut ma, &ctx(&dev_a, &files_a, &pk, &sk, &signer))
            .await
            .unwrap();

        // B manages a *different* path only; its push must not erase A's
        // entry from the shared manifest.
        let work_b = TempDir::new().unwrap();
        std::fs::create_dir_all(work_b.path().join("other")).unwrap();
        std::fs::write(work_b.path().join("other/g"), b"from-b").unwrap();
        let files_b = vec![mf(&work_b, "other/g")];
        let mut mb = Manifest::new("B");
        sync(&store, &mut mb, &ctx(&dev_b, &files_b, &pk, &sk, &signer))
            .await
            .unwrap();

        // B's local manifest holds only what it manages — but the pushed
        // manifest must still carry A's entry, proven by a third device
        // managing vim/f pulling A's file AFTER B's push.
        assert!(
            !mb.entries.contains_key(&ConfigPath::new("vim/f")),
            "unmanaged entries must not be adopted into local state"
        );
        let work_c = TempDir::new().unwrap();
        let files_c = vec![mf(&work_c, "vim/f")];
        let mut mc = Manifest::new("C");
        let dev_c = DeviceId::new("C");
        sync(&store, &mut mc, &ctx(&dev_c, &files_c, &pk, &sk, &signer))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(work_c.path().join("vim/f")).unwrap(),
            b"from-a",
            "A's entry must survive B's subset push"
        );

        // Regression: a device that *later* starts managing a path it has
        // been preserving must pull the content — treating the entry as
        // already-synced (adoption into local state) would skip the fetch.
        let files_b2 = vec![mf(&work_b, "vim/f"), mf(&work_b, "other/g")];
        sync(&store, &mut mb, &ctx(&dev_b, &files_b2, &pk, &sk, &signer))
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(work_b.path().join("vim/f")).unwrap(),
            b"from-a",
            "newly managed path must pull its content"
        );
    }
}

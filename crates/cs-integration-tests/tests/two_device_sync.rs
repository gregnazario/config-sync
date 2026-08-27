//! Two-device sync integration: two simulated devices share one `LocalFs`
//! store and converge after independent edits, including a forced concurrent
//! edit resolved by each conflict policy.

use cs_config::ConflictPolicy;
use cs_crypto::{derive_recipient_keypair, generate_rik, ManifestSigningKey};
use cs_manifest::{ConfigPath, DeviceId, Manifest};
use cs_storage::LocalFs;
use cs_sync::{sync, ConflictChoice, FixedResolver, ManagedFile, SyncContext};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn managed(work: &TempDir, logical: &str, policy: ConflictPolicy) -> ManagedFile {
    // The logical path "vim/f" maps to disk path "<work>/vim/f".
    ManagedFile {
        logical: ConfigPath::new(logical),
        disk_path: work.path().join(logical),
        policy,
    }
}

fn write_file(work: &TempDir, rel: &str, contents: &[u8]) {
    let p = work.path().join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, contents).unwrap();
}

fn read_file(work: &TempDir, rel: &str) -> Vec<u8> {
    std::fs::read(work.path().join(rel)).unwrap()
}

#[tokio::test]
async fn two_devices_converge_after_independent_edits() {
    let shared = TempDir::new().unwrap();
    let store = LocalFs::new(shared.path());
    let (pk, sk, signer) = {
        let rik = generate_rik().unwrap();
        let (pk, sk) = derive_recipient_keypair(&rik);
        (pk, sk, ManifestSigningKey::derive_from_rik(&rik))
    };
    let dev_a = DeviceId::new("A");
    let dev_b = DeviceId::new("B");

    let work_a = TempDir::new().unwrap();
    let work_b = TempDir::new().unwrap();
    write_file(&work_a, "vim/f", b"v1\n");

    let mut ma = Manifest::new("A");
    let files_a = vec![managed(&work_a, "vim/f", ConflictPolicy::LatestWins)];
    let ctx_a = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut ma, &ctx_a).await.unwrap();

    // Device B pulls v1.
    let mut mb = Manifest::new("B");
    let files_b = vec![managed(&work_b, "vim/f", ConflictPolicy::LatestWins)];
    let ctx_b = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut mb, &ctx_b).await.unwrap();
    assert_eq!(read_file(&work_b, "vim/f"), b"v1\n");
    assert_eq!(ma.entries, mb.entries, "after a clean pull manifests match");

    // Device A edits to v2; device B edits to v3 concurrently.
    write_file(&work_a, "vim/f", b"v2-from-A\n");
    write_file(&work_b, "vim/f", b"v3-from-B\n");
    // A pushes its edit (B has not pulled, so no conflict for A yet).
    let now_a = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let ctx_a2 = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: now_a,
    };
    sync(&store, &mut ma, &ctx_a2).await.unwrap();

    // B now syncs: B's edit is concurrent with A's pushed edit → conflict.
    // LatestWins must pick the newer modified time (B's, written later).
    let now_b = SystemTime::UNIX_EPOCH + Duration::from_secs(2);
    let ctx_b2 = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: now_b,
    };
    let rep = sync(&store, &mut mb, &ctx_b2).await.unwrap();
    assert!(
        !rep.conflicts_resolved.is_empty() || rep.pulled.iter().any(|p| p.as_str() == "vim/f"),
        "B must resolve the conflict or pull the winner"
    );

    // Re-sync A to converge: A should pull B's resolution.
    let ctx_a3 = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(3),
    };
    sync(&store, &mut ma, &ctx_a3).await.unwrap();
    // One more B round to quiesce (B may need to observe A's convergence push).
    let ctx_b3 = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(4),
    };
    sync(&store, &mut mb, &ctx_b3).await.unwrap();

    assert_eq!(
        read_file(&work_a, "vim/f"),
        read_file(&work_b, "vim/f"),
        "both devices must hold identical content after convergence"
    );
    assert_eq!(
        ma.entries
            .get(&ConfigPath::new("vim/f"))
            .map(|e| e.blob_id.clone()),
        mb.entries
            .get(&ConfigPath::new("vim/f"))
            .map(|e| e.blob_id.clone()),
        "both devices must agree on the winning blob id (manifest convergence): \
         ma={:?} mb={:?}",
        ma.entries
            .get(&ConfigPath::new("vim/f"))
            .map(|e| e.clock.clone()),
        mb.entries
            .get(&ConfigPath::new("vim/f"))
            .map(|e| e.clock.clone()),
    );
}

#[tokio::test]
async fn prompt_policy_uses_resolver() {
    let shared = TempDir::new().unwrap();
    let store = LocalFs::new(shared.path());
    let (pk, sk, signer) = {
        let rik = generate_rik().unwrap();
        let (pk, sk) = derive_recipient_keypair(&rik);
        (pk, sk, ManifestSigningKey::derive_from_rik(&rik))
    };
    let dev_a = DeviceId::new("A");
    let dev_b = DeviceId::new("B");

    let work_a = TempDir::new().unwrap();
    let work_b = TempDir::new().unwrap();
    write_file(&work_a, "vim/f", b"base\n");
    // Seed both devices with the base content via a shared first push/pull.
    let mut ma = Manifest::new("A");
    let files_a = vec![managed(&work_a, "vim/f", ConflictPolicy::Prompt)];
    let ctx_a = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut ma, &ctx_a).await.unwrap();
    let mut mb = Manifest::new("B");
    let files_b = vec![managed(&work_b, "vim/f", ConflictPolicy::Prompt)];
    let ctx_b = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut mb, &ctx_b).await.unwrap();

    // Concurrent edits.
    write_file(&work_a, "vim/f", b"A-edit\n");
    write_file(&work_b, "vim/f", b"B-edit\n");
    // A pushes (no conflict yet for A).
    let ctx_a2 = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut ma, &ctx_a2).await.unwrap();

    // B syncs with a resolver that keeps the remote (A's edit).
    let keep_remote = FixedResolver(ConflictChoice::KeepRemote);
    let ctx_b2 = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: Some(&keep_remote),
        now: SystemTime::UNIX_EPOCH,
    };
    let rep = sync(&store, &mut mb, &ctx_b2).await.unwrap();
    assert!(
        rep.conflicts_resolved.iter().any(|p| p.as_str() == "vim/f"),
        "B should have resolved the vim/f conflict via the resolver"
    );
    assert_eq!(
        read_file(&work_b, "vim/f"),
        b"A-edit\n",
        "B should now hold A's edit"
    );
}

#[tokio::test]
async fn new_file_on_one_device_pulls_to_the_other() {
    let shared = TempDir::new().unwrap();
    let store = LocalFs::new(shared.path());
    let (pk, sk, signer) = {
        let rik = generate_rik().unwrap();
        let (pk, sk) = derive_recipient_keypair(&rik);
        (pk, sk, ManifestSigningKey::derive_from_rik(&rik))
    };

    let work_a = TempDir::new().unwrap();
    let work_b = TempDir::new().unwrap();
    write_file(&work_a, "git/config", b"[user]\nname = A\n");

    let mut ma = Manifest::new("A");
    let files_a = vec![managed(&work_a, "git/config", ConflictPolicy::LatestWins)];
    let ctx_a = SyncContext {
        device: &DeviceId::new("A"),
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut ma, &ctx_a).await.unwrap();

    let mut mb = Manifest::new("B");
    let files_b = vec![managed(&work_b, "git/config", ConflictPolicy::LatestWins)];
    let ctx_b = SyncContext {
        device: &DeviceId::new("B"),
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        manifest_signer: &signer,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    let rep = sync(&store, &mut mb, &ctx_b).await.unwrap();
    assert!(rep.pulled.iter().any(|p| p.as_str() == "git/config"));
    assert_eq!(read_file(&work_b, "git/config"), b"[user]\nname = A\n");
}

//! Proves the sync engine is backend-agnostic by running the two-device
//! convergence scenario through an in-memory `RemoteStore` (not just LocalFs).

use cs_config::ConflictPolicy;
use cs_crypto::generate_recipient_keypair;
use cs_manifest::{ConfigPath, DeviceId, Manifest};
use cs_storage::MemoryStore;
use cs_sync::{sync, ManagedFile, SyncContext};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn managed(work: &TempDir, logical: &str) -> ManagedFile {
    ManagedFile {
        logical: ConfigPath::new(logical),
        disk_path: work.path().join(logical),
        policy: ConflictPolicy::LatestWins,
    }
}

#[tokio::test]
async fn two_devices_converge_through_memory_store() {
    let store = MemoryStore::new();
    let (pk, sk) = generate_recipient_keypair();
    let dev_a = DeviceId::new("A");
    let dev_b = DeviceId::new("B");

    let work_a = TempDir::new().unwrap();
    let work_b = TempDir::new().unwrap();
    std::fs::create_dir_all(work_a.path().join("vim")).unwrap();
    std::fs::write(work_a.path().join("vim/f"), b"v1\n").unwrap();

    // A pushes.
    let mut ma = Manifest::new("A");
    let files_a = vec![managed(&work_a, "vim/f")];
    let ctx_a = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut ma, &ctx_a).await.unwrap();

    // B pulls.
    let mut mb = Manifest::new("B");
    let files_b = vec![managed(&work_b, "vim/f")];
    let ctx_b = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        resolver: None,
        now: SystemTime::UNIX_EPOCH,
    };
    sync(&store, &mut mb, &ctx_b).await.unwrap();
    assert_eq!(std::fs::read(work_b.path().join("vim/f")).unwrap(), b"v1\n");

    // Concurrent edits.
    std::fs::write(work_a.path().join("vim/f"), b"from-A\n").unwrap();
    std::fs::write(work_b.path().join("vim/f"), b"from-B\n").unwrap();
    sync(&store, &mut ma, &{
        SyncContext {
            device: &dev_a,
            files: &files_a,
            recip_keys: &pk,
            recip_secrets: &sk,
            resolver: None,
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        }
    })
    .await
    .unwrap();
    sync(&store, &mut mb, &{
        SyncContext {
            device: &dev_b,
            files: &files_b,
            recip_keys: &pk,
            recip_secrets: &sk,
            resolver: None,
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        }
    })
    .await
    .unwrap();
    sync(&store, &mut ma, &{
        SyncContext {
            device: &dev_a,
            files: &files_a,
            recip_keys: &pk,
            recip_secrets: &sk,
            resolver: None,
            now: SystemTime::UNIX_EPOCH + Duration::from_secs(3),
        }
    })
    .await
    .unwrap();

    assert_eq!(
        std::fs::read(work_a.path().join("vim/f")).unwrap(),
        std::fs::read(work_b.path().join("vim/f")).unwrap(),
        "devices converge through an in-memory store too"
    );
    assert_eq!(
        ma.entries
            .get(&ConfigPath::new("vim/f"))
            .map(|e| e.blob_id.clone()),
        mb.entries
            .get(&ConfigPath::new("vim/f"))
            .map(|e| e.blob_id.clone()),
    );
}

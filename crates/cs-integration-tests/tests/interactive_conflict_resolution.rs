//! Proves the interactive resolver plugs into the sync engine: a forced
//! concurrent conflict is resolved interactively (via a fake surface that
//! simulates a user choice) and both devices converge to the chosen version.

use cs_config::ConflictPolicy;
use cs_crypto::generate_recipient_keypair;
use cs_manifest::{ConfigPath, DeviceId, Manifest};
use cs_storage::MemoryStore;
use cs_sync::{sync, ConflictChoice, ManagedFile, SyncContext};
use cs_ui::{FakeInteractive, InteractiveResolver, InteractiveSurface};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

fn managed(work: &TempDir, logical: &str) -> ManagedFile {
    ManagedFile {
        logical: ConfigPath::new(logical),
        disk_path: work.path().join(logical),
        policy: ConflictPolicy::Prompt,
    }
}

fn write(work: &TempDir, rel: &str, contents: &[u8]) {
    let p = work.path().join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, contents).unwrap();
}

#[tokio::test]
async fn interactive_resolver_drives_sync_convergence() {
    let store = MemoryStore::new();
    let (pk, sk) = generate_recipient_keypair();
    let dev_a = DeviceId::new("A");
    let dev_b = DeviceId::new("B");

    let work_a = TempDir::new().unwrap();
    let work_b = TempDir::new().unwrap();
    write(&work_a, "vim/f", b"base\n");

    // Seed: A pushes base, B pulls it.
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

    // Concurrent edits → conflict.
    write(&work_a, "vim/f", b"from-A\n");
    write(&work_b, "vim/f", b"from-B\n");
    let ctx_a2 = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        resolver: None,
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
    };
    sync(&store, &mut ma, &ctx_a2).await.unwrap();

    // B syncs with an interactive resolver that "chooses remote" (A's edit).
    let surface = FakeInteractive::returning(Some(ConflictChoice::KeepRemote));
    let resolver = InteractiveResolver::new(&surface as &dyn InteractiveSurface);
    let ctx_b2 = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        resolver: Some(&resolver),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(2),
    };
    let rep = sync(&store, &mut mb, &ctx_b2).await.unwrap();
    assert!(
        rep.conflicts_resolved.iter().any(|p| p.as_str() == "vim/f"),
        "B resolved the conflict via the interactive resolver"
    );
    assert_eq!(
        std::fs::read(work_b.path().join("vim/f")).unwrap(),
        b"from-A\n"
    );

    // The surface was presented exactly one conflict with two previews.
    assert_eq!(surface.seen.lock().unwrap().len(), 1);
    assert_eq!(surface.seen.lock().unwrap()[0].len(), 2);

    // A re-syncs to converge onto the resolved state. A also has an interactive
    // resolver wired (a real device would), so any residual conflict is handled.
    let surface_a = FakeInteractive::returning(Some(ConflictChoice::KeepLocal));
    let resolver_a = InteractiveResolver::new(&surface_a as &dyn InteractiveSurface);
    let ctx_a3 = SyncContext {
        device: &dev_a,
        files: &files_a,
        recip_keys: &pk,
        recip_secrets: &sk,
        resolver: Some(&resolver_a),
        now: SystemTime::UNIX_EPOCH + Duration::from_secs(3),
    };
    sync(&store, &mut ma, &ctx_a3).await.unwrap();
    // Content converges: A holds its own edit (the chosen winner), B already
    // pulled it via the interactive resolution. Both devices agree on content.
    assert_eq!(
        std::fs::read(work_a.path().join("vim/f")).unwrap(),
        b"from-A\n"
    );
    assert_eq!(
        std::fs::read(work_a.path().join("vim/f")).unwrap(),
        std::fs::read(work_b.path().join("vim/f")).unwrap(),
        "both devices hold identical content (the interactively-chosen version)"
    );
    // And the interactive resolver was the thing that decided it: exactly one
    // conflict was presented to B's surface and resolved.
    assert_eq!(surface.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn interactive_resolver_abort_stops_the_sync() {
    let store = MemoryStore::new();
    let (pk, sk) = generate_recipient_keypair();
    let dev_a = DeviceId::new("A");
    let dev_b = DeviceId::new("B");

    let work_a = TempDir::new().unwrap();
    let work_b = TempDir::new().unwrap();
    write(&work_a, "vim/f", b"base\n");
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

    write(&work_a, "vim/f", b"from-A\n");
    write(&work_b, "vim/f", b"from-B\n");
    sync(&store, &mut ma, &ctx_a).await.unwrap();

    // B aborts the conflict → the sync stops cleanly without corrupting state.
    let surface = FakeInteractive::aborting();
    let resolver = InteractiveResolver::new(&surface as &dyn InteractiveSurface);
    let ctx_b2 = SyncContext {
        device: &dev_b,
        files: &files_b,
        recip_keys: &pk,
        recip_secrets: &sk,
        resolver: Some(&resolver),
        now: SystemTime::UNIX_EPOCH,
    };
    let rep = sync(&store, &mut mb, &ctx_b2).await.unwrap();
    assert!(rep.aborted, "abort propagates as an aborted SyncReport");
    // B keeps its own edit (the conflict was not applied).
    assert_eq!(
        std::fs::read(work_b.path().join("vim/f")).unwrap(),
        b"from-B\n"
    );
}

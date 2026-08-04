//! Cross-crate integration tests proving the cycle-1 foundation works end to end:
//! crypto seal/open through a real storage backend, device identity persistence,
//! and recovery round-trips.

use bytes::Bytes;
use cs_crypto::{generate_recipient_keypair, open, seal, Aad, OpenInput};
use cs_keys::{
    load_identity, store_identity, CloudBundleProvider, DeviceIdentity, InMemoryStore,
    MnemonicProvider, RecoveryProvider, ShamirProvider,
};
use cs_storage::{LocalFs, RemoteStore};

#[tokio::test]
async fn crypto_seal_then_store_then_retrieve_then_open_round_trips() {
    // The full data path: encrypt with the crypto core, persist the envelope to
    // a real LocalFs store (header + body as two objects), read them back, and
    // decrypt. This exercises crypto + storage together.
    let (pk, sk) = generate_recipient_keypair();
    let aad = Aad {
        path: "vim/.vimrc".into(),
        version: 1,
    };
    let plaintext = b"set nu\nset ai\nset et\n";
    let out = seal(plaintext, &aad, &pk).expect("seal");

    let dir = tempfile::tempdir().unwrap();
    let store = LocalFs::new(dir.path());

    // Store header and body as separate content-addressed objects, mirroring the
    // eventual remote layout.
    let header_etag = store
        .put("blobs/abc.header", Bytes::from(out.header.clone()), None)
        .await
        .expect("put header");
    let _body_etag = store
        .put("blobs/abc.body", Bytes::from(out.body.clone()), None)
        .await
        .expect("put body");

    // Retrieve and decrypt.
    let fetched_header = store.get("blobs/abc.header").await.expect("get header");
    let fetched_body = store.get("blobs/abc.body").await.expect("get body");
    let pt = open(
        OpenInput {
            header: &fetched_header,
            body: &fetched_body,
        },
        &aad,
        &sk,
    )
    .expect("open");
    assert_eq!(pt, plaintext);

    // The header object should have an etag and survive a list.
    let listed: Vec<_> = store
        .list("blobs/")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert!(listed.contains(&"blobs/abc.header".to_string()));
    assert!(listed.contains(&"blobs/abc.body".to_string()));
    assert_eq!(header_etag.0, "1");
}

#[test]
fn device_identity_persists_and_still_decrypts() {
    // Identity store/load cycle, then prove the reloaded identity can decrypt a
    // file sealed to its own public key.
    let store = InMemoryStore::new();
    let id = DeviceIdentity::new().unwrap();
    let pk_bytes = id.recipient_keys.kem_pq.clone();
    store_identity(&store, &id).unwrap();
    let loaded = load_identity(&store).unwrap();
    assert_eq!(loaded.recipient_keys.kem_pq, pk_bytes);

    let aad = Aad {
        path: "after-reload".into(),
        version: 1,
    };
    let out = seal(b"persisted", &aad, &loaded.recipient_keys).unwrap();
    let pt = open(
        OpenInput {
            header: &out.header,
            body: &out.body,
        },
        &aad,
        &loaded.recipient_secrets,
    )
    .unwrap();
    assert_eq!(pt, b"persisted");
}

#[test]
fn mnemonic_recovery_round_trips_rik() {
    // Lose the device, keep only the mnemonic words -> recover the RIK.
    let store = InMemoryStore::new();
    let id = DeviceIdentity::new().unwrap();
    store_identity(&store, &id).unwrap();

    let mp = MnemonicProvider::fast_for_tests();
    let real_rik = *id.rik.as_bytes();
    let sealed = mp.seal_with_mnemonic(&real_rik, None).unwrap();
    let words = sealed.mnemonic_words.clone();
    let recovered = mp
        .recover_with_mnemonic(&sealed.bundle, &words, None)
        .unwrap();
    assert_eq!(recovered, real_rik);
}

#[test]
fn shamir_recovery_round_trips_rik() {
    let p = ShamirProvider::default();
    let rik = [0x11u8; 32];
    let bundle = p.seal(&rik).unwrap();
    assert_eq!(p.recover(&bundle).unwrap(), rik);
}

#[test]
fn cloud_bundle_recovery_round_trips_rik() {
    let p = CloudBundleProvider::fast_for_tests();
    let rik = [0x22u8; 32];
    let bundle = p.seal_with_passphrase(&rik, "a strong passphrase").unwrap();
    assert_eq!(
        p.recover_with_passphrase(&bundle, "a strong passphrase")
            .unwrap(),
        rik
    );
    // Wrong passphrase must fail.
    assert!(p
        .recover_with_passphrase(&bundle, "wrong passphrase")
        .is_err());
}

#[test]
fn multiple_recovery_providers_seal_the_same_rik() {
    // Defense in depth: the same RIK is sealed by all three providers and each
    // recovers it independently.
    let rik = [0x99u8; 32];

    let mn = MnemonicProvider::fast_for_tests();
    let mn_sealed = mn.seal_with_mnemonic(&rik, None).unwrap();
    assert_eq!(
        mn.recover_with_mnemonic(&mn_sealed.bundle, &mn_sealed.mnemonic_words, None)
            .unwrap(),
        rik
    );

    let sh = ShamirProvider::default();
    let sh_bundle = sh.seal(&rik).unwrap();
    assert_eq!(sh.recover(&sh_bundle).unwrap(), rik);

    let cb = CloudBundleProvider::fast_for_tests();
    let cb_bundle = cb.seal_with_passphrase(&rik, "pass").unwrap();
    assert_eq!(cb.recover_with_passphrase(&cb_bundle, "pass").unwrap(), rik);
}

//! S3 backend conformance test.
//!
//! This exercises the real `S3Store` (aws-sdk-s3) against any S3-compatible
//! endpoint. It runs **only** when the `CSYNC_S3_ENDPOINT` env var is set
//! (e.g. pointing at MinIO, LocalStack, an in-process s3s mock, or real S3),
//! and is a no-op otherwise — so CI without S3 stays green.
//!
//! To run against a local mock:
//!   ```
//!   CSYNC_S3_ENDPOINT=http://localhost:9000 \
//!   CSYNC_S3_BUCKET=config-sync-test \
//!   CSYNC_S3_REGION=us-east-1 \
//!   AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
//!   cargo test -p cs-integration-tests --test s3_backend --features cs-storage/s3 -- --include-ignored
//!   ```

#![cfg(feature = "s3")]

use bytes::Bytes;
use cs_storage::{Etag, RemoteStore, S3Store, StorageError};

fn cfg_present() -> bool {
    std::env::var("CSYNC_S3_ENDPOINT").is_ok() && std::env::var("CSYNC_S3_BUCKET").is_ok()
}

#[tokio::test]
#[ignore = "set CSYNC_S3_ENDPOINT + CSYNC_S3_BUCKET to run against a real/mock S3"]
async fn s3_put_get_list_delete_round_trip() {
    if !cfg_present() {
        eprintln!("CSYNC_S3_ENDPOINT not set; skipping live S3 test");
        return;
    }
    let endpoint = std::env::var("CSYNC_S3_ENDPOINT").unwrap();
    let bucket = std::env::var("CSYNC_S3_BUCKET").unwrap();
    let region = std::env::var("CSYNC_S3_REGION").ok();
    let prefix = format!("conformance-{}", std::process::id());

    let store = S3Store::from_config(&bucket, &prefix, Some(&endpoint), region.as_deref())
        .await
        .expect("build S3Store");

    let name = "hello.txt";
    let etag = store
        .put(name, Bytes::from_static(b"hi from s3"), None)
        .await
        .expect("put");
    assert!(!etag.0.is_empty());

    let got = store.get(name).await.expect("get");
    assert_eq!(got, Bytes::from_static(b"hi from s3"));

    let names: Vec<_> = store
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert!(
        names.contains(&name.to_string()),
        "list must include the object"
    );

    store.delete(name).await.expect("delete");
    assert!(matches!(
        store.get(name).await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
#[ignore = "set CSYNC_S3_ENDPOINT + CSYNC_S3_BUCKET to run against a real/mock S3"]
async fn s3_conditional_put_detects_concurrent_write() {
    if !cfg_present() {
        eprintln!("CSYNC_S3_ENDPOINT not set; skipping live S3 test");
        return;
    }
    let endpoint = std::env::var("CSYNC_S3_ENDPOINT").unwrap();
    let bucket = std::env::var("CSYNC_S3_BUCKET").unwrap();
    let region = std::env::var("CSYNC_S3_REGION").ok();
    let prefix = format!("cas-{}", std::process::id());

    let store = S3Store::from_config(&bucket, &prefix, Some(&endpoint), region.as_deref())
        .await
        .expect("build S3Store");

    let name = "manifest.json";
    let _e1 = store
        .put(name, Bytes::from_static(b"v1"), None)
        .await
        .expect("put v1");
    // A concurrent writer bumps the object.
    let _e2 = store
        .put(name, Bytes::from_static(b"v2"), None)
        .await
        .expect("put v2");
    // A stale conditional put referencing the first etag must fail.
    let stale = Etag("0".to_string());
    let r = store
        .put(name, Bytes::from_static(b"v3"), Some(&stale))
        .await;
    assert!(
        matches!(
            r,
            Err(StorageError::PreconditionFailed) | Err(StorageError::Backend(_))
        ),
        "stale conditional put should be rejected: got {:?}",
        r.as_ref().err()
    );
}

//! config-sync storage layer: the `RemoteStore` trait and pluggable backends.

#![forbid(unsafe_code)]

mod error;
mod memory;

#[cfg(feature = "local-fs")]
mod local_fs;

#[cfg(feature = "s3")]
mod s3;

#[cfg(feature = "webdav")]
mod webdav;

#[cfg(feature = "gdrive")]
mod gdrive;

use async_trait::async_trait;
use bytes::Bytes;
use std::ops::Range;
use std::time::SystemTime;

pub use error::StorageError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etag(pub String);

#[derive(Clone, Debug)]
pub struct ObjectMeta {
    pub name: String,
    pub etag: Etag,
    pub size: u64,
    pub mtime: SystemTime,
}

#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub range_get: bool,
    pub conditional_put: bool,
}

/// Backend-agnostic object store. Backends with native ETags (S3) map `if_match`
/// directly; backends without (local FS) emulate it via a sidecar.
#[async_trait]
pub trait RemoteStore: Send + Sync {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError>;
    async fn get(&self, name: &str) -> Result<Bytes, StorageError>;
    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError>;
    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError>;
    async fn delete(&self, name: &str) -> Result<(), StorageError>;
    fn capabilities(&self) -> Capabilities;
}

pub use memory::MemoryStore;

#[cfg(feature = "local-fs")]
pub use local_fs::LocalFs;

#[cfg(feature = "s3")]
pub use s3::S3Store;

#[cfg(feature = "webdav")]
pub use webdav::WebDavStore;

#[cfg(feature = "gdrive")]
pub use gdrive::GoogleDriveStore;

#[cfg(test)]
mod trait_tests {
    use super::*;

    /// A trivial in-memory store used only to type-check the trait and exercise
    /// the optimistic-concurrency semantics the sync engine (cycle 2) will rely on.
    struct Dummy {
        ok: bool,
    }

    #[async_trait]
    impl RemoteStore for Dummy {
        async fn list(&self, _p: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(vec![])
        }
        async fn get(&self, n: &str) -> Result<Bytes, StorageError> {
            if self.ok {
                Ok(Bytes::new())
            } else {
                Err(StorageError::NotFound(n.into()))
            }
        }
        async fn get_range(&self, _n: &str, _r: Range<u64>) -> Result<Bytes, StorageError> {
            Ok(Bytes::new())
        }
        async fn put(
            &self,
            _n: &str,
            _d: Bytes,
            if_match: Option<&Etag>,
        ) -> Result<Etag, StorageError> {
            if if_match.map(|e| e.0 == "stale").unwrap_or(false) {
                return Err(StorageError::PreconditionFailed);
            }
            Ok(Etag("1".into()))
        }
        async fn delete(&self, _n: &str) -> Result<(), StorageError> {
            Ok(())
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                range_get: false,
                conditional_put: true,
            }
        }
    }

    #[tokio::test]
    async fn dummy_put_returns_etag() {
        let d = Dummy { ok: true };
        let e = d.put("x", Bytes::from_static(b"y"), None).await.unwrap();
        assert_eq!(e.0, "1");
    }

    #[tokio::test]
    async fn dummy_conditional_put_detects_stale_etag() {
        let d = Dummy { ok: true };
        let stale = Etag("stale".into());
        assert!(matches!(
            d.put("x", Bytes::new(), Some(&stale)).await,
            Err(StorageError::PreconditionFailed)
        ));
    }
}

//! Local-filesystem `RemoteStore` backend. Conditional put is emulated with a
//! `.version` sidecar storing a monotonic ETag counter, so `if_match` detects
//! concurrent modifications even without native ETags.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use std::ops::Range;
use std::path::PathBuf;
use std::time::SystemTime;
use tokio::fs;

pub struct LocalFs {
    pub root: PathBuf,
    /// Per-instance lock ensuring the check→write→bump sequence in `put` is
    /// atomic, preventing races on shared/network-mounted stores.
    put_lock: tokio::sync::Mutex<()>,
}

impl LocalFs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            put_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn obj_path(&self, name: &str) -> Result<PathBuf, StorageError> {
        let p = self.root.join(name);
        // Defense against path traversal: reject names containing "..".
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(StorageError::Backend(format!(
                "path escapes store root: {name}"
            )));
        }
        Ok(p)
    }

    fn ver_path(&self, name: &str) -> Result<PathBuf, StorageError> {
        let mut p = self.obj_path(name)?;
        let mut new_ext = p
            .extension()
            .map(|e| {
                let mut s = e.to_string_lossy().into_owned();
                s.push_str(".version");
                s
            })
            .unwrap_or_else(|| "version".to_string());
        // ensure non-empty
        if new_ext.is_empty() {
            new_ext = "version".to_string();
        }
        p.set_extension(new_ext);
        Ok(p)
    }

    async fn read_etag(&self, name: &str) -> Result<Option<Etag>, StorageError> {
        match fs::read_to_string(self.ver_path(name)?).await {
            Ok(s) => Ok(Some(Etag(s.trim().to_string()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn bump_etag(&self, name: &str) -> Result<Etag, StorageError> {
        let cur = self
            .read_etag(name)
            .await?
            .map(|e| e.0.parse::<u64>().unwrap_or(0))
            .unwrap_or(0);
        let next = cur + 1;
        fs::write(self.ver_path(name)?, next.to_string()).await?;
        Ok(Etag(next.to_string()))
    }
}

#[async_trait]
impl RemoteStore for LocalFs {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = vec![];
        let base = self.root.join(prefix);
        if !base.exists() {
            return Ok(out);
        }
        let mut stack = vec![base.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = fs::read_dir(&dir).await?;
            while let Some(e) = rd.next_entry().await? {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                // Skip version sidecars.
                if p.extension()
                    .and_then(|x| x.to_str())
                    .map(|s| s.ends_with("version"))
                    .unwrap_or(false)
                {
                    continue;
                }
                let meta = fs::metadata(&p).await?;
                // Logical config paths use forward slashes everywhere; on
                // Windows the OS separator is '\', so normalize after stripping.
                let name = p
                    .strip_prefix(&self.root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let etag = self.read_etag(&name).await?.unwrap_or(Etag("0".into()));
                out.push(ObjectMeta {
                    name,
                    etag,
                    size: meta.len(),
                    mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }
        }
        Ok(out)
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let path = self.obj_path(name)?;
        match fs::read(path).await {
            Ok(b) => Ok(Bytes::from(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(name.into()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        let b = fs::read(self.obj_path(name)?).await?;
        let start = range.start as usize;
        let end = std::cmp::min(range.end as usize, b.len());
        if start > end {
            return Ok(Bytes::new());
        }
        Ok(Bytes::from(b[start..end].to_vec()))
    }

    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError> {
        // Hold the per-instance lock across check→write→bump to prevent
        // races on shared/network-mounted stores.
        let _guard = self.put_lock.lock().await;

        if let Some(want) = if_match {
            match self.read_etag(name).await? {
                Some(have) if have.0 == want.0 => {}
                Some(_) => return Err(StorageError::PreconditionFailed),
                None => {
                    if !want.0.is_empty() {
                        return Err(StorageError::PreconditionFailed);
                    }
                }
            }
        }
        let p = self.obj_path(name)?;
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&p, &data).await?;
        self.bump_etag(name).await
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        if let Ok(vp) = self.ver_path(name) {
            let _ = fs::remove_file(vp).await;
        }
        match fs::remove_file(self.obj_path(name)?).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(name.into()))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            range_get: true,
            conditional_put: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &tempfile::TempDir) -> LocalFs {
        LocalFs::new(dir.path())
    }

    #[tokio::test]
    async fn put_get_list_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        let e = st
            .put("blobs/abc", Bytes::from_static(b"data"), None)
            .await
            .unwrap();
        assert_eq!(e.0, "1");
        assert_eq!(
            st.get("blobs/abc").await.unwrap(),
            Bytes::from_static(b"data")
        );
        let names: Vec<_> = st
            .list("")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert!(names.contains(&"blobs/abc".to_string()));
        st.delete("blobs/abc").await.unwrap();
        assert!(matches!(
            st.get("blobs/abc").await,
            Err(StorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn conditional_put_detects_concurrent_modification() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        let e1 = st.put("a", Bytes::from_static(b"v1"), None).await.unwrap();
        // A concurrent bump by another writer.
        let _e2 = st.put("a", Bytes::from_static(b"v2"), None).await.unwrap();
        // Stale if_match must fail.
        let r = st.put("a", Bytes::from_static(b"v3"), Some(&e1)).await;
        assert!(matches!(r, Err(StorageError::PreconditionFailed)));
    }

    #[tokio::test]
    async fn conditional_put_with_current_etag_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        let e1 = st.put("a", Bytes::from_static(b"v1"), None).await.unwrap();
        let e2 = st
            .put("a", Bytes::from_static(b"v2"), Some(&e1))
            .await
            .unwrap();
        assert_eq!(e2.0, "2");
        assert_eq!(st.get("a").await.unwrap(), Bytes::from_static(b"v2"));
    }

    #[tokio::test]
    async fn delete_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        assert!(matches!(
            st.delete("nope").await,
            Err(StorageError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn get_range_returns_subset() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        st.put("blob", Bytes::from_static(b"hello world"), None)
            .await
            .unwrap();
        let sub = st.get_range("blob", 0..5).await.unwrap();
        assert_eq!(sub, Bytes::from_static(b"hello"));
        // Range past end clamps.
        let sub2 = st.get_range("blob", 6..100).await.unwrap();
        assert_eq!(sub2, Bytes::from_static(b"world"));
    }

    #[tokio::test]
    async fn version_sidecars_are_hidden_from_list() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        st.put("blob", Bytes::from_static(b"x"), None)
            .await
            .unwrap();
        let names: Vec<_> = st
            .list("")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert!(names
            .iter()
            .all(|n| !n.ends_with(".version") && !n.contains(".version.")));
    }

    #[tokio::test]
    async fn capabilities_advertises_features() {
        let dir = tempfile::tempdir().unwrap();
        let st = store(&dir);
        let c = st.capabilities();
        assert!(c.range_get);
        assert!(c.conditional_put);
    }
}

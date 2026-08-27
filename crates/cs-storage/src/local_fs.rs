//! Local-filesystem `RemoteStore` backend. Conditional put is emulated with a
//! `.version` sidecar storing a monotonic ETag counter, so `if_match` detects
//! concurrent modifications even without native ETags.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::fs;

pub struct LocalFs {
    pub root: PathBuf,
    /// Per-process lock serializing the check→write→bump sequence in `put`.
    /// A per-`name` OS-level file lock (flock) additionally serializes
    /// *cross-process* writers — two `config-sync` processes (or two machines
    /// on a network-mounted store) cannot both pass the `if_match` check and
    /// then blindly overwrite each other.
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
        // Defense against path traversal and store-escape. `Path::join` with
        // an absolute right-hand side *replaces* the root, so absolute names
        // and `..` components are both rejected explicitly, as are Windows
        // path separators smuggled into a name.
        if name.is_empty()
            || name.starts_with('/')
            || name.starts_with('\\')
            || name.contains('\\')
            || name.contains('\0')
            || std::path::Path::new(name).is_absolute()
            || name.split('/').any(|seg| seg == ".." || seg == ".")
        {
            return Err(StorageError::Backend(format!(
                "object name escapes store root: {name:?}"
            )));
        }
        let p = self.root.join(name);
        // Check the *name's* own components: the joined path legitimately
        // contains RootDir/Prefix because `root` is absolute.
        if std::path::Path::new(name).components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::CurDir
            )
        }) {
            return Err(StorageError::Backend(format!(
                "object name escapes store root: {name:?}"
            )));
        }
        Ok(p)
    }

    /// Acquire the cross-process advisory lock guarding CAS operations.
    /// Held for the (short) check→write→bump critical section.
    fn cas_lock(&self) -> Result<fd_lock::RwLock<std::fs::File>, StorageError> {
        let lock_path = self.root.join(".cas.lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            // 0600: with default perms any local user could open the lock
            // file and hold LOCK_EX, permanently stalling every writer.
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(&lock_path)?
        };
        #[cfg(not(unix))]
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        Ok(fd_lock::RwLock::new(file))
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

    /// Write `data` to `path` atomically: a fresh temp file in the same
    /// directory (created 0600 on Unix), fsynced, then renamed over the
    /// target. A crash can never leave a truncated object behind, and a
    /// symlink planted at the target is *replaced* rather than followed.
    async fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StorageError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "object".to_string());
        let mut nonce = [0u8; 4];
        let _ = getrandom::fill(&mut nonce);
        let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", hex::encode(nonce)));

        #[cfg(unix)]
        let wrote = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            Ok(())
        })();

        #[cfg(not(unix))]
        let wrote = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            Ok(())
        })();

        if let Err(e) = wrote {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        fs::rename(&tmp, path).await?;
        Ok(())
    }

    /// Pre-read validation: the object must be a regular file (not a
    /// symlink — a planted symlink to /dev/zero would OOM the reader, a FIFO
    /// would hang it) and within the size cap. Only ciphertext lives here,
    /// and honest blobs are far below the cap.
    fn validate_object_for_read(path: &Path) -> Result<std::fs::Metadata, StorageError> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            // The caller maps a missing object to NotFound; preserve that.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(path.to_string_lossy().into_owned()))
            }
            Err(e) => return Err(e.into()),
        };
        let ft = meta.file_type();
        if ft.is_symlink() || !ft.is_file() {
            return Err(StorageError::Backend(
                "store object is not a regular file (symlink or special file planted?)".into(),
            ));
        }
        const MAX_LOCAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
        if meta.len() > MAX_LOCAL_OBJECT_BYTES {
            return Err(StorageError::Backend(format!(
                "store object of {} bytes exceeds the read cap",
                meta.len()
            )));
        }
        Ok(meta)
    }

    async fn bump_etag(&self, name: &str) -> Result<Etag, StorageError> {
        let cur = self
            .read_etag(name)
            .await?
            .map(|e| e.0.parse::<u64>().unwrap_or(0))
            .unwrap_or(0);
        let next = cur + 1;
        Self::atomic_write(&self.ver_path(name)?, next.to_string().as_bytes()).await?;
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
                // Use the entry's own file type: a symlinked directory must
                // NOT be followed (a planted symlink could otherwise make the
                // walk escape into — or hang on — the wider filesystem).
                let is_symlink_dir = matches!(
                    e.file_type().await,
                    Ok(ft) if ft.is_symlink()
                );
                if is_symlink_dir {
                    continue;
                }
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                // Skip version sidecars, the CAS lock, and temp files.
                let file_name = p.file_name().map(|n| n.to_string_lossy().into_owned());
                if let Some(n) = &file_name {
                    if n == ".cas.lock" || (n.starts_with('.') && n.ends_with(".tmp")) {
                        continue;
                    }
                }
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
        Self::validate_object_for_read(&path)?;
        match fs::read(path).await {
            Ok(b) => Ok(Bytes::from(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(name.into()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        let path = self.obj_path(name)?;
        Self::validate_object_for_read(&path)?;
        let b = fs::read(path).await?;
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
        // Per-process lock first (cheap), then the cross-process OS lock so
        // the check→write→bump sequence is atomic even against other
        // config-sync processes sharing this store directory.
        let _guard = self.put_lock.lock().await;
        let mut cas_lock = self.cas_lock()?;
        let _cas_guard = cas_lock
            .write()
            .map_err(|e| StorageError::Backend(format!("cas lock: {e}")))?;

        if let Some(want) = if_match {
            match self.read_etag(name).await? {
                Some(have) if have.0 == want.0 => {}
                Some(_) => return Err(StorageError::PreconditionFailed),
                None => {
                    // No sidecar: "must be absent" (empty expected etag) only
                    // passes when the object itself is absent too.
                    let exists = self.obj_path(name).map(|p| p.exists()).unwrap_or(false);
                    if !want.0.is_empty() || exists {
                        return Err(StorageError::PreconditionFailed);
                    }
                }
            }
        }
        let p = self.obj_path(name)?;
        Self::atomic_write(&p, &data).await?;
        self.bump_etag(name).await
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        // Same critical section as put: an unlocked delete interleaving with
        // a concurrent put's check→write→bump could resurrect a deleted
        // object or leave a stale version sidecar.
        let _guard = self.put_lock.lock().await;
        let mut cas_lock = self.cas_lock()?;
        let _cas_guard = cas_lock
            .write()
            .map_err(|e| StorageError::Backend(format!("cas lock: {e}")))?;
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

//! In-memory `RemoteStore` — a faithful test double and contract-conformance
//! target. Supports conditional put via per-object version counters, mirroring
//! the semantics backends like S3 expose via ETags.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Mutex;
use std::time::SystemTime;

#[derive(Default)]
struct Inner {
    // name -> (version_counter, bytes)
    objects: BTreeMap<String, (u64, Bytes)>,
}

#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RemoteStore for MemoryStore {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let inner = self.inner.lock().unwrap();
        let mut out = Vec::new();
        for (name, (ver, data)) in &inner.objects {
            if name.starts_with(prefix) {
                out.push(ObjectMeta {
                    name: name.clone(),
                    etag: Etag(ver.to_string()),
                    size: data.len() as u64,
                    mtime: SystemTime::UNIX_EPOCH,
                });
            }
        }
        Ok(out)
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let inner = self.inner.lock().unwrap();
        inner
            .objects
            .get(name)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| StorageError::NotFound(name.to_string()))
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        let inner = self.inner.lock().unwrap();
        let b = inner
            .objects
            .get(name)
            .map(|(_, b)| b.clone())
            .ok_or_else(|| StorageError::NotFound(name.to_string()))?;
        let start = range.start as usize;
        let end = std::cmp::min(range.end as usize, b.len());
        if start > end {
            return Ok(Bytes::new());
        }
        Ok(b.slice(start..end))
    }

    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(want) = if_match {
            match inner.objects.get(name) {
                Some((ver, _)) => {
                    if want.0 != ver.to_string() {
                        return Err(StorageError::PreconditionFailed);
                    }
                }
                None => {
                    if !want.0.is_empty() {
                        return Err(StorageError::PreconditionFailed);
                    }
                }
            }
        }
        let next = inner.objects.get(name).map(|(v, _)| v + 1).unwrap_or(1);
        inner.objects.insert(name.to_string(), (next, data));
        Ok(Etag(next.to_string()))
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let mut inner = self.inner.lock().unwrap();
        match inner.objects.remove(name) {
            Some(_) => Ok(()),
            None => Err(StorageError::NotFound(name.to_string())),
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

    #[tokio::test]
    async fn round_trip_and_cas() {
        let s = MemoryStore::new();
        let e1 = s.put("a", Bytes::from_static(b"v1"), None).await.unwrap();
        assert_eq!(e1.0, "1");
        assert_eq!(s.get("a").await.unwrap(), Bytes::from_static(b"v1"));
        let _e2 = s.put("a", Bytes::from_static(b"v2"), None).await.unwrap();
        assert!(matches!(
            s.put("a", Bytes::from_static(b"v3"), Some(&e1)).await,
            Err(StorageError::PreconditionFailed)
        ));
        let names: Vec<_> = s
            .list("")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert!(names.contains(&"a".to_string()));
        s.delete("a").await.unwrap();
        assert!(matches!(s.get("a").await, Err(StorageError::NotFound(_))));
    }
}

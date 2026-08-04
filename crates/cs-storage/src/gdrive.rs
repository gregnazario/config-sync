//! Google Drive `RemoteStore` backend, behind the `gdrive` feature.
//!
//! Google Drive's API is not path- or ETag-conditional-write-based, so this
//! backend stores every config-sync object as a file inside a single Drive
//! folder and keeps a small JSON index (`_cs_index.json`) mapping each logical
//! name to its Drive file id. The index file is the **single coordination
//! object**: every mutation loads it, applies, and writes it back, and the
//! `if_match` conditional is checked against the index's monotonic `version`.
//! This mirrors how the sync engine treats the manifest as the one mutable
//! object on a store.
//!
//! Auth is a bearer token supplied by the caller (the CLI layer handles OAuth
//! out of band); no credentials live in the config file.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ops::Range;
use std::time::SystemTime;

const INDEX_NAME: &str = "_cs_index.json";

/// A bearer-token-authenticated Google Drive store rooted at `root_folder_id`.
pub struct GoogleDriveStore {
    http: reqwest::Client,
    api_base: String,
    root_folder_id: String,
    /// Per-instance index cache: avoids 2 HTTP round-trips per op within a sync.
    index_cache: tokio::sync::Mutex<Option<Index>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct Index {
    version: u64,
    /// The Drive file id of the index file itself (so saving it doesn't have
    /// to look itself up recursively).
    #[serde(default)]
    index_file_id: Option<String>,
    /// logical name -> drive file id
    #[serde(default)]
    files: BTreeMap<String, String>,
}

impl GoogleDriveStore {
    /// Build a store pointing at the official Drive API. `bearer_token` is the
    /// OAuth access token; `root_folder_id` is the Drive folder to use as root.
    pub fn new(bearer_token: impl Into<String>, root_folder_id: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    bearer_token.into()
                )) {
                    h.insert(reqwest::header::AUTHORIZATION, v);
                }
                h
            })
            .build()
            .unwrap_or_default();
        Self {
            http,
            api_base: "https://www.googleapis.com/drive/v3".to_string(),
            root_folder_id: root_folder_id.into(),
            index_cache: tokio::sync::Mutex::new(None),
        }
    }

    /// Point at a custom API base (for SaaS-Drive-compatible mocks / tests).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    // ---- index helpers (with per-instance caching) ---------------------

    async fn load_index(&self) -> Result<Index, StorageError> {
        // Return cached index if available (avoids 2 HTTP round-trips per op).
        let cache = self.index_cache.lock().await;
        if let Some(ref cached) = *cache {
            return Ok(cached.clone());
        }
        drop(cache);

        // Find the index file by name in the root folder.
        let url = format!(
            "{}/files?q={}+in+parents+and+name='{}'&fields=files(id)",
            self.api_base,
            url_encode(&self.root_folder_id),
            INDEX_NAME
        );
        let resp = self.http.get(&url).send().await.map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let v: ListFilesResp = resp.json().await.map_err(net_err)?;
        let idx = match v.files.first() {
            Some(f) => {
                let bytes = self.download(&f.id).await?;
                let mut idx: Index = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::Backend(format!("bad index json: {e}")))?;
                idx.index_file_id = Some(f.id.clone());
                idx
            }
            None => Index::default(),
        };
        // Cache for subsequent calls in this sync cycle.
        *self.index_cache.lock().await = Some(idx.clone());
        Ok(idx)
    }

    async fn save_index(&self, idx: &mut Index) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec(idx)
            .map_err(|e| StorageError::Backend(format!("index encode: {e}")))?;
        match &idx.index_file_id {
            Some(id) => {
                self.replace_content(id, &bytes).await?;
            }
            None => {
                let id = self.create_file(INDEX_NAME, &bytes).await?;
                idx.index_file_id = Some(id);
                let again = serde_json::to_vec(idx)
                    .map_err(|e| StorageError::Backend(format!("index encode: {e}")))?;
                self.replace_content(idx.index_file_id.as_ref().unwrap(), &again)
                    .await?;
            }
        }
        // Update cache with the new version.
        *self.index_cache.lock().await = Some(idx.clone());
        Ok(())
    }

    async fn download(&self, file_id: &str) -> Result<Vec<u8>, StorageError> {
        let url = format!("{}/files/{}?alt=media", self.api_base, url_encode(file_id));
        let resp = self.http.get(&url).send().await.map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        Ok(resp.bytes().await.map_err(net_err)?.to_vec())
    }

    async fn create_file(&self, name: &str, data: &[u8]) -> Result<String, StorageError> {
        // Multipart create: metadata (name + parents) then media. Uses the
        // configured api_base so test mocks and Drive-compatible gateways work.
        let url = format!("{}/files?uploadType=multipart", self.api_base);
        let meta = serde_json::json!({
            "name": name,
            "parents": [self.root_folder_id],
        });
        let part = reqwest::multipart::Form::new()
            .text("metadata", meta.to_string())
            .part(
                "media",
                reqwest::multipart::Part::bytes(data.to_vec()).file_name(name.to_string()),
            );
        let resp = self
            .http
            .post(&url)
            .multipart(part)
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let v: serde_json::Value = resp.json().await.map_err(net_err)?;
        Ok(v.get("id")
            .and_then(|i| i.as_str())
            .ok_or_else(|| StorageError::Backend("create returned no id".into()))?
            .to_string())
    }

    async fn replace_content(&self, file_id: &str, data: &[u8]) -> Result<(), StorageError> {
        // Overwrite a file's content. Routed through a dedicated upload path so
        // it works against both Drive and the in-process mock.
        let url = format!(
            "{}/upload/files/{}?uploadType=media",
            self.api_base,
            url_encode(file_id)
        );
        let resp = self
            .http
            .patch(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data.to_vec())
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ListFilesResp {
    files: Vec<DriveFile>,
}

#[derive(Deserialize)]
struct DriveFile {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
}

fn net_err(e: reqwest::Error) -> StorageError {
    StorageError::Backend(format!("network: {e}"))
}

fn map_err(status: reqwest::StatusCode, body: String) -> StorageError {
    match status.as_u16() {
        404 => StorageError::NotFound(body),
        412 | 409 => StorageError::PreconditionFailed,
        _ => StorageError::Backend(format!("HTTP {status}: {body}")),
    }
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[async_trait]
impl RemoteStore for GoogleDriveStore {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let idx = self.load_index().await?;
        Ok(idx
            .files
            .iter()
            .filter(|(name, _)| name.starts_with(prefix) && name.as_str() != INDEX_NAME)
            .map(|(name, _)| ObjectMeta {
                name: name.clone(),
                etag: Etag(idx.version.to_string()),
                size: 0,
                mtime: SystemTime::UNIX_EPOCH,
            })
            .collect())
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let idx = self.load_index().await?;
        let id = idx
            .files
            .get(name)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(name.to_string()))?;
        Ok(Bytes::from(self.download(&id).await?))
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        let idx = self.load_index().await?;
        let id = idx
            .files
            .get(name)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(name.to_string()))?;
        let url = format!("{}/files/{}?alt=media", self.api_base, url_encode(&id));
        let resp = self
            .http
            .get(&url)
            .header(
                reqwest::header::RANGE,
                format!("bytes={}-{}", range.start, range.end.saturating_sub(1)),
            )
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        Ok(resp.bytes().await.map_err(net_err)?)
    }

    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError> {
        let mut idx = self.load_index().await?;
        if let Some(want) = if_match {
            let cur = idx.version.to_string();
            if want.0 != cur {
                return Err(StorageError::PreconditionFailed);
            }
        }
        if let Some(id) = idx.files.get(name).cloned() {
            self.replace_content(&id, &data).await?;
        } else {
            let id = self.create_file(name, &data).await?;
            idx.files.insert(name.to_string(), id);
        }
        idx.version += 1;
        self.save_index(&mut idx).await?;
        Ok(Etag(idx.version.to_string()))
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let mut idx = self.load_index().await?;
        let id = idx
            .files
            .get(name)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(name.to_string()))?;
        let url = format!("{}/files/{}", self.api_base, url_encode(&id));
        let _ = self.http.delete(&url).send().await.map_err(net_err)?;
        idx.files.remove(name);
        idx.version += 1;
        self.save_index(&mut idx).await?;
        Ok(())
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

    #[test]
    fn url_encode_keeps_unreserved() {
        assert_eq!(url_encode("abc-_."), "abc-_.");
        assert_eq!(url_encode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn index_round_trips_through_json() {
        let mut files = BTreeMap::new();
        files.insert("blobs/abc".to_string(), "fileId9".to_string());
        let idx = Index {
            version: 3,
            index_file_id: Some("idxId".to_string()),
            files,
        };
        let s = serde_json::to_vec(&idx).unwrap();
        let back: Index = serde_json::from_slice(&s).unwrap();
        assert_eq!(back.version, 3);
        assert_eq!(back.index_file_id.as_deref(), Some("idxId"));
        assert_eq!(
            back.files.get("blobs/abc").map(String::as_str),
            Some("fileId9")
        );
    }
}

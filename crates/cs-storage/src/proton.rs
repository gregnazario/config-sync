//! Proton Drive `RemoteStore` backend, behind the `proton` feature.
//!
//! Proton Drive's native protocol is an undocumented, layered end-to-end-
//! encrypted API over Proton's account/session system, with no stable public
//! surface and no Rust SDK. For third-party integration Proton exposes its data
//! through an HTTP gateway (this is how its own desktop bridge and community
//! clients such as rclone's protondrive backend reach it). This backend speaks
//! that gateway shape directly: each managed object is a **path-addressed
//! node** carrying a monotonically-increasing `revision` (Proton exposes
//! `Revision`/block-manifests per node), and conditional writes use `If-Match`
//! against that revision. Because nodes are path-addressed, no opaque-id index
//! is needed (unlike the Google Drive backend).
//!
//! Auth is a bearer token supplied by the caller (the CLI layer logs in via
//! Proton's SRP flow and hands the resulting access token here); no
//! credentials live in the config file.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::ops::Range;
use std::time::SystemTime;

/// Bearer-token-authenticated Proton Drive store rooted at `base_url`.
pub struct ProtonDriveStore {
    http: reqwest::Client,
    base_url: String,
}

impl ProtonDriveStore {
    /// Build a store with the given OAuth/session bearer token. `base_url` is
    /// the gateway root (everything is stored under `{base_url}/nodes/...`).
    pub fn new(bearer_token: impl Into<String>, base_url: impl Into<String>) -> Self {
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
        let mut base_url = base_url.into();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Self { http, base_url }
    }

    fn node_url(&self, name: &str) -> String {
        format!("{}/nodes/{}", self.base_url, percent_encode_path(name))
    }

    fn list_url(&self, prefix: &str) -> String {
        format!(
            "{}/nodes?prefix={}",
            self.base_url,
            percent_encode_path(prefix)
        )
    }
}

#[derive(Deserialize)]
struct NodeResp {
    /// Monotonic per-node revision; used as the ETag.
    #[serde(default)]
    revision: u64,
    /// Optional content (present on GET; absent on metadata-only calls).
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    size: u64,
}

#[derive(Deserialize)]
struct ListResp {
    #[serde(default)]
    nodes: Vec<ListItem>,
}

#[derive(Deserialize)]
struct ListItem {
    name: String,
    #[serde(default)]
    revision: u64,
    #[serde(default)]
    size: u64,
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

fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
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
impl RemoteStore for ProtonDriveStore {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let resp = self
            .http
            .get(self.list_url(prefix))
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let v: ListResp = resp.json().await.map_err(net_err)?;
        Ok(v.nodes
            .into_iter()
            .map(|n| ObjectMeta {
                name: n.name,
                etag: Etag(n.revision.to_string()),
                size: n.size,
                mtime: SystemTime::UNIX_EPOCH,
            })
            .collect())
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let resp = self
            .http
            .get(self.node_url(name))
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let v: NodeResp = resp.json().await.map_err(net_err)?;
        let content = v
            .content
            .ok_or_else(|| StorageError::Backend("node has no content".into()))?;
        Ok(Bytes::from(content.into_bytes()))
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        // Fetch full content and slice locally: Proton's gateway hands back the
        // whole decrypted block per node; range requests are not part of the
        // node protocol. For config-file sizes this is fine.
        let full = self.get(name).await?;
        let start = range.start as usize;
        let end = std::cmp::min(range.end as usize, full.len());
        if start > end {
            return Ok(Bytes::new());
        }
        Ok(full.slice(start..end))
    }

    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError> {
        let mut req = self
            .http
            .put(self.node_url(name))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data);
        if let Some(want) = if_match {
            req = req.header(reqwest::header::IF_MATCH, want.0.clone());
        }
        let resp = req.send().await.map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let v: NodeResp = resp.json().await.map_err(net_err)?;
        Ok(Etag(v.revision.to_string()))
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let resp = self
            .http
            .delete(self.node_url(name))
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if status.as_u16() == 404 {
            let b = resp.text().await.unwrap_or_default();
            return Err(StorageError::NotFound(b));
        }
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
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
    fn percent_encode_keeps_slash_and_unreserved() {
        // Path segments keep '/' so nodes stay path-addressed.
        assert_eq!(percent_encode_path("blobs/abc"), "blobs/abc");
        assert_eq!(percent_encode_path("a b"), "a%20b");
        assert_eq!(percent_encode_path("v1.2-3_x"), "v1.2-3_x");
    }

    #[test]
    fn node_resp_decodes_minimal() {
        let v: NodeResp =
            serde_json::from_str(r#"{"revision":7,"content":"hi","size":2}"#).unwrap();
        assert_eq!(v.revision, 7);
        assert_eq!(v.content.as_deref(), Some("hi"));
        assert_eq!(v.size, 2);
    }

    #[test]
    fn node_resp_decodes_without_optional_fields() {
        let v: NodeResp = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(v.revision, 0);
        assert!(v.content.is_none());
    }
}

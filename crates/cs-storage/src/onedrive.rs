//! Microsoft OneDrive `RemoteStore` backend, behind the `onedrive` feature.
//!
//! Speaks the Microsoft Graph API (OneDrive's public, documented REST surface):
//! each object is a **path-addressed** drive item, and conditional writes use
//! `If-Match` against the item's `eTag`. Path-addressing means no opaque-id
//! index is needed (unlike Google Drive). Auth is a bearer token supplied by
//! the caller (the CLI layer handles the OAuth flow with Microsoft); no
//! credentials live in the config file.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;
use std::ops::Range;
use std::time::SystemTime;

const GRAPH_BASE: &str = "https://graph.microsoft.com/v1.0";

/// Bearer-token-authenticated OneDrive store.
pub struct OneDriveStore {
    http: reqwest::Client,
    base_url: String,
}

impl OneDriveStore {
    /// Build a store with the given OAuth access token. Talks to the official
    /// Microsoft Graph endpoint.
    pub fn new(bearer_token: impl Into<String>) -> Self {
        Self::with_base_and_token(bearer_token, GRAPH_BASE)
    }

    /// Point at a custom Graph base (for national clouds or test mocks).
    pub fn with_base_and_token(
        bearer_token: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
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
            base_url: base_url.into(),
        }
    }

    /// URL for the content endpoint of a path-addressed item:
    /// `{base}/me/drive/root:/<path>:/content`
    fn content_url(&self, name: &str) -> String {
        format!(
            "{}/me/drive/root:/{}:/content",
            self.base_url,
            encode_path(name)
        )
    }

    /// URL for the item metadata endpoint:
    /// `{base}/me/drive/root:/<path>`
    fn item_url(&self, name: &str) -> String {
        format!("{}/me/drive/root:/{}", self.base_url, encode_path(name))
    }

    /// URL for listing children of a folder:
    /// `{base}/me/drive/root:/<prefix>:/children` (or `root:/children` for the
    /// root folder when prefix is empty).
    fn children_url(&self, prefix: &str) -> String {
        if prefix.is_empty() {
            format!("{}/me/drive/root:/children", self.base_url)
        } else {
            format!(
                "{}/me/drive/root:/{}:/children",
                self.base_url,
                encode_path(prefix)
            )
        }
    }
}

#[derive(Deserialize)]
struct DriveItem {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "eTag")]
    etag: Option<String>,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize)]
struct ChildrenResp {
    #[serde(default)]
    value: Vec<DriveItem>,
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

/// Percent-encode a path for use in the `:/path:` Graph segment, keeping `/`.
fn encode_path(s: &str) -> String {
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
impl RemoteStore for OneDriveStore {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let resp = self
            .http
            .get(self.children_url(prefix))
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let v: ChildrenResp = resp.json().await.map_err(net_err)?;
        Ok(v.value
            .into_iter()
            .map(|item| ObjectMeta {
                name: if prefix.is_empty() {
                    item.name
                } else {
                    format!("{}/{}", prefix.trim_end_matches('/'), item.name)
                },
                etag: Etag(item.etag.unwrap_or_else(|| "0".into())),
                size: item.size,
                mtime: SystemTime::UNIX_EPOCH,
            })
            .collect())
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let resp = self
            .http
            .get(self.content_url(name))
            .send()
            .await
            .map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        Ok(resp.bytes().await.map_err(net_err)?)
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        // OneDrive supports the Range header on content downloads.
        let resp = self
            .http
            .get(self.content_url(name))
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
        let mut req = self
            .http
            .put(self.content_url(name))
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(data);
        if let Some(want) = if_match {
            // OneDrive returns eTags wrapped in double quotes; If-Match uses them as-is.
            req = req.header(reqwest::header::IF_MATCH, want.0.clone());
        }
        let resp = req.send().await.map_err(net_err)?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_err(status, resp.text().await.unwrap_or_default()));
        }
        let item: DriveItem = resp.json().await.map_err(net_err)?;
        Ok(Etag(item.etag.unwrap_or_else(|| "0".into())))
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let resp = self
            .http
            .delete(self.item_url(name))
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
    fn encode_path_keeps_slash_and_unreserved() {
        assert_eq!(encode_path("blobs/abc"), "blobs/abc");
        assert_eq!(encode_path("a b"), "a%20b");
        assert_eq!(encode_path("v1.2-3_x"), "v1.2-3_x");
    }

    #[test]
    fn children_url_for_empty_prefix() {
        let s = OneDriveStore::with_base_and_token("tok", "https://graph.test");
        assert_eq!(
            s.children_url(""),
            "https://graph.test/me/drive/root:/children"
        );
    }

    #[test]
    fn children_url_for_prefix() {
        let s = OneDriveStore::with_base_and_token("tok", "https://graph.test");
        assert_eq!(
            s.children_url("blobs"),
            "https://graph.test/me/drive/root:/blobs:/children"
        );
    }

    #[test]
    fn drive_item_decodes_minimal() {
        let v: DriveItem = serde_json::from_str(r#"{"name":"a","eTag":"\"x\"","size":5}"#).unwrap();
        assert_eq!(v.name, "a");
        assert_eq!(v.etag.as_deref(), Some("\"x\""));
        assert_eq!(v.size, 5);
    }
}

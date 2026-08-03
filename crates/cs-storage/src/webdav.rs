//! WebDAV `RemoteStore` backend, behind the `webdav` feature.
//!
//! Speaks the WebDAV subset that config-sync needs: `PUT`, `GET`, `DELETE`,
//! and `PROPFIND` (Depth: 1), with conditional writes via the `If-Match`
//! header. This single backend therefore works against any WebDAV server —
//! Nextcloud, ownCloud, Synology WebDAV, box.com, and iCloud Drive (which
//! exposes a WebDAV endpoint), covering several of the objective's named
//! "upload locations" with one implementation.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use std::ops::Range;
use std::sync::Arc;
use std::time::SystemTime;

/// A WebDAV-backed store. `base_url` is the collection URL everything is
/// stored under (e.g. `https://cloud.example.com/remote.php/dav/files/user/config-sync/`).
pub struct WebDavStore {
    http: reqwest::Client,
    base_url: String,
}

impl WebDavStore {
    pub fn new(http: reqwest::Client, base_url: impl Into<String>) -> Result<Self, StorageError> {
        let mut base_url = base_url.into();
        if !base_url.ends_with('/') {
            base_url.push('/');
        }
        Ok(Self { http, base_url })
    }

    fn url(&self, name: &str) -> String {
        // Names use forward slashes; URL-encode the path segments but keep the
        // separators. Names never start with '/' (the trait contract uses keys
        // like "blobs/abc"), so we just append.
        let mut out = self.base_url.clone();
        for (i, seg) in name.split('/').enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(&percent_encode(seg));
        }
        out
    }

    /// Extract the ETag from a response (stripping surrounding quotes).
    fn etag_of(resp: &reqwest::Response) -> Etag {
        resp.headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .map(Etag)
            .unwrap_or(Etag("0".to_string()))
    }
}

fn percent_encode(segment: &str) -> String {
    // Minimal RFC 3986 segment encoder: keep unreserved chars, percent-encode
    // the rest. Avoids pulling in a `percent-encoding` crate dep.
    let mut out = String::with_capacity(segment.len());
    for &b in segment.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
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

fn map_http_err(status: reqwest::StatusCode, body: String) -> StorageError {
    match status.as_u16() {
        404 => StorageError::NotFound(body),
        412 => StorageError::PreconditionFailed,
        _ => StorageError::Backend(format!("HTTP {status}: {body}")),
    }
}

#[async_trait]
impl RemoteStore for WebDavStore {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        // PROPFIND with Depth: 1 on the prefix collection, parse <D:href> and
        // <D:getetag> / <D:getcontentlength> from the multistatus XML body.
        let url = self.url(prefix);
        let body = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:getcontentlength/></D:prop></D:propfind>"#;
        let resp = self
            .http
            .request(reqwest::Method::from_bytes(b"PROPFIND").unwrap(), &url)
            .header("Depth", "1")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/xml; charset=utf-8",
            )
            .body(body)
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let b = resp.text().await.unwrap_or_default();
            return Err(map_http_err(status, b));
        }
        let text = resp.text().await.unwrap_or_default();
        Ok(parse_multistatus(&text, &self.base_url, prefix))
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let resp = self
            .http
            .get(self.url(name))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let b = resp.text().await.unwrap_or_default();
            return Err(map_http_err(status, b));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(bytes)
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        let resp = self
            .http
            .get(self.url(name))
            .header(
                reqwest::header::RANGE,
                format!("bytes={}-{}", range.start, range.end.saturating_sub(1)),
            )
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let b = resp.text().await.unwrap_or_default();
            return Err(map_http_err(status, b));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(bytes)
    }

    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError> {
        let mut req = self.http.put(self.url(name)).body(data);
        if let Some(want) = if_match {
            if want.0.is_empty() {
                // "must be absent": use If-None-Match: *
                req = req.header(reqwest::header::IF_NONE_MATCH, "*");
            } else {
                req = req.header(reqwest::header::IF_MATCH, format!("\"{}\"", want.0));
            }
        }
        let resp = req
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let b = resp.text().await.unwrap_or_default();
            return Err(map_http_err(status, b));
        }
        Ok(Self::etag_of(&resp))
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let resp = self
            .http
            .delete(self.url(name))
            .send()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            let b = resp.text().await.unwrap_or_default();
            return Err(StorageError::NotFound(b));
        }
        if !status.is_success() {
            let b = resp.text().await.unwrap_or_default();
            return Err(map_http_err(status, b));
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

/// Parse a WebDAV multistatus body into `ObjectMeta` entries, stripping the
/// base URL prefix so returned names match the keys the engine uses.
fn parse_multistatus(xml: &str, base_url: &str, prefix: &str) -> Vec<ObjectMeta> {
    let mut out = Vec::new();
    // Walk <D:response> blocks. We avoid a full XML parser dep by scanning for
    // the well-known tags; WebDAV servers produce stable, machine-generated XML.
    for resp_block in xml.split("<D:response>").skip(1) {
        let block = resp_block.split("</D:response>").next().unwrap_or("");
        let href = extract_tag(block, "D:href").or_else(|| extract_tag(block, "d:href"));
        let etag = extract_tag(block, "D:getetag")
            .or_else(|| extract_tag(block, "d:getetag"))
            .map(|s| s.trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "0".to_string());
        let size = extract_tag(block, "D:getcontentlength")
            .or_else(|| extract_tag(block, "d:getcontentlength"))
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if let Some(h) = href {
            // The href may be a full URL, an absolute path, or relative. Decode
            // it, then strip the base URL *or* the path portion of the base URL.
            let decoded = url_decode(&h);
            let base_path = base_url
                .find("://")
                .and_then(|i| base_url[i + 3..].find('/'))
                .map(|j| {
                    let start = base_url.find("://").unwrap() + 3 + j;
                    &base_url[start..]
                })
                .unwrap_or(base_url);
            let name = decoded
                .strip_prefix(base_url)
                .or_else(|| decoded.strip_prefix(base_path))
                .or_else(|| decoded.strip_prefix(prefix))
                .unwrap_or(&decoded)
                .trim_end_matches('/')
                .to_string();
            if !name.is_empty() {
                out.push(ObjectMeta {
                    name,
                    etag: Etag(etag),
                    size,
                    mtime: SystemTime::UNIX_EPOCH,
                });
            }
        }
    }
    out
}

fn extract_tag(block: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    Some(block[start..end].to_string())
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

// Keep the Arc import used in case future revisions share the client; for now
// it documents the intended sharing pattern.
#[allow(dead_code)]
type _SharedClient = Arc<reqwest::Client>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_keeps_unreserved() {
        assert_eq!(percent_encode("abc-._~"), "abc-._~");
        assert_eq!(percent_encode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn parse_multistatus_extracts_entries() {
        let xml = r#"<?xml version="1.0"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>https://host/base/blobs/abc</D:href>
    <D:propstat><D:prop><D:getetag>"v1"</D:getetag><D:getcontentlength>42</D:getcontentlength></D:prop></D:propstat>
  </D:response>
  <D:response>
    <D:href>https://host/base/manifest.json</D:href>
    <D:propstat><D:prop><D:getetag>"v2"</D:getetag><D:getcontentlength>9</D:getcontentlength></D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;
        let entries = parse_multistatus(xml, "https://host/base/", "");
        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|e| e.name == "blobs/abc" && e.size == 42));
        assert!(entries
            .iter()
            .any(|e| e.name == "manifest.json" && e.etag.0 == "v2"));
    }
}

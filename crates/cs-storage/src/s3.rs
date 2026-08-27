//! AWS S3 (and S3-compatible) `RemoteStore` backend, behind the `s3` feature.
//!
//! Auth follows the standard AWS credential chain (env, shared config, IMDS);
//! no credentials ever live in the config file. A custom endpoint can be
//! supplied for S3-compatible stores (MinIO, Cloudflare R2, Backblaze B2,
//! LocalStack, …) or for tests pointing at an in-process mock.

use crate::{Capabilities, Etag, ObjectMeta, RemoteStore, StorageError};
use async_trait::async_trait;
use aws_sdk_s3::Client;
use bytes::Bytes;
use std::ops::Range;

/// S3-backed `RemoteStore`. All keys live under `prefix` within `bucket`.
pub struct S3Store {
    client: Client,
    bucket: String,
    prefix: String,
}

impl S3Store {
    pub fn new(client: Client, bucket: impl Into<String>, prefix: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            prefix: normalize_prefix(prefix.into()),
        }
    }

    /// Build from the default AWS credential/config chain, optionally pointing
    /// at a custom `endpoint_url` (for S3-compatible stores or test mocks).
    pub async fn from_config(
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        endpoint_url: Option<&str>,
        region: Option<&str>,
    ) -> Result<Self, StorageError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(ep) = endpoint_url {
            loader = loader.endpoint_url(ep);
        }
        if let Some(r) = region {
            loader = loader.region(aws_sdk_s3::config::Region::new(r.to_string()));
        }
        let cfg = loader.load().await;
        let mut s3_cfg = aws_sdk_s3::config::Builder::from(&cfg);
        // S3-compatible stores often need path-style addressing.
        if endpoint_url.is_some() {
            s3_cfg = s3_cfg.force_path_style(true);
        }
        let client = Client::from_conf(s3_cfg.build());
        Ok(Self::new(client, bucket, prefix))
    }

    fn full_key(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}{}", self.prefix, name)
        }
    }

    /// Collect a response body chunk-by-chunk under the size cap. A hostile
    /// endpoint can omit or lie about Content-Length, so the header check
    /// alone is not enough — every chunk is counted.
    async fn collect_capped(
        mut body: aws_sdk_s3::primitives::ByteStream,
        name: &str,
    ) -> Result<Bytes, StorageError> {
        let mut out: Vec<u8> = Vec::new();
        while let Some(chunk) = body
            .next()
            .await
            .transpose()
            .map_err(|e| StorageError::Backend(e.to_string()))?
        {
            if out.len() + chunk.len() > MAX_OBJECT_BYTES {
                return Err(StorageError::Backend(format!(
                    "object '{name}' exceeds the {MAX_OBJECT_BYTES}-byte cap"
                )));
            }
            out.extend_from_slice(&chunk);
        }
        Ok(Bytes::from(out))
    }

    fn strip_prefix<'a>(&'a self, key: &'a str) -> &'a str {
        key.strip_prefix(&self.prefix).unwrap_or(key)
    }
}

fn normalize_prefix(mut p: String) -> String {
    if !p.is_empty() && !p.ends_with('/') {
        p.push('/');
    }
    p
}

/// Classify an SDK error by its HTTP status when a response is available
/// (reliable for every modeled S3 error — NoSuchKey/NoSuchBucket are 404,
/// failed preconditions are 412), falling back to matching the modeled error
/// code in the Display form for transport-level errors that carry no
/// response.
fn classify_err(status: Option<u16>, msg: String) -> StorageError {
    match status {
        Some(404) => return StorageError::NotFound(msg),
        Some(412) => return StorageError::PreconditionFailed,
        _ => {}
    }
    let lower = msg.to_ascii_lowercase();
    if lower.contains("nosuchkey") || lower.contains("nosuchbucket") || lower.contains("notfound") {
        return StorageError::NotFound(msg);
    }
    if lower.contains("preconditionfailed") {
        return StorageError::PreconditionFailed;
    }
    StorageError::Backend(msg)
}

/// Extract the HTTP status and Display form from any per-operation SDK error
/// in one step (the status comes from the raw response, so real 412s from S3
/// are never misclassified by their message wording).
fn map_err<E>(
    e: aws_smithy_runtime_api::client::result::SdkError<E, aws_smithy_runtime_api::http::Response>,
) -> StorageError
where
    E: std::fmt::Display,
{
    let status = e.raw_response().map(|r| r.status().as_u16());
    classify_err(status, e.to_string())
}

/// Upper bound on a single GET response. Anything larger is a hostile or
/// broken endpoint.
const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
/// Pagination bounds: a hostile endpoint must not be able to force an
/// infinite listing loop with unbounded result growth.
const MAX_LIST_PAGES: usize = 10_000;
const MAX_LIST_KEYS: usize = 1_000_000;

#[async_trait]
impl RemoteStore for S3Store {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let full = self.full_key(prefix);
        let mut out = Vec::new();
        let mut cont: Option<String> = None;
        let mut pages = 0usize;
        loop {
            pages += 1;
            if pages > MAX_LIST_PAGES || out.len() > MAX_LIST_KEYS {
                return Err(StorageError::Backend(
                    "listing exceeded pagination bounds (hostile or broken endpoint?)".into(),
                ));
            }
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full);
            if let Some(c) = &cont {
                req = req.continuation_token(c.clone());
            }
            let resp = req.send().await.map_err(map_err)?;
            for obj in resp.contents() {
                if let Some(key) = obj.key() {
                    let name = self.strip_prefix(key).to_string();
                    let etag = obj.e_tag().unwrap_or("0").trim_matches('"').to_string();
                    out.push(ObjectMeta {
                        name,
                        etag: Etag(etag),
                        size: obj.size.unwrap_or(0) as u64,
                        mtime: std::time::SystemTime::UNIX_EPOCH,
                    });
                }
            }
            match resp.is_truncated() {
                Some(true) => {
                    let next = resp.next_continuation_token().map(|s| s.to_string());
                    // A repeated token means the endpoint is re-serving the
                    // same page forever — bail instead of looping.
                    if next.is_none() || next == cont {
                        break;
                    }
                    cont = next;
                }
                _ => break,
            }
        }
        Ok(out)
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let key = self.full_key(name);
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(map_err)?;
        if resp.content_length().unwrap_or(0) > MAX_OBJECT_BYTES as i64 {
            return Err(StorageError::Backend(format!(
                "object '{name}' of {} bytes exceeds the size cap",
                resp.content_length().unwrap_or_default()
            )));
        }
        Ok(Self::collect_capped(resp.body, name).await?)
    }

    async fn get_range(&self, name: &str, range: Range<u64>) -> Result<Bytes, StorageError> {
        let key = self.full_key(name);
        let range_hdr = format!("bytes={}-{}", range.start, range.end.saturating_sub(1));
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(range_hdr)
            .send()
            .await
            .map_err(map_err)?;
        if resp.content_length().unwrap_or(0) > MAX_OBJECT_BYTES as i64 {
            return Err(StorageError::Backend(format!(
                "object '{name}' range of {} bytes exceeds the size cap",
                resp.content_length().unwrap_or_default()
            )));
        }
        Ok(Self::collect_capped(resp.body, name).await?)
    }

    async fn put(
        &self,
        name: &str,
        data: Bytes,
        if_match: Option<&Etag>,
    ) -> Result<Etag, StorageError> {
        let key = self.full_key(name);
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(data.into());
        if let Some(want) = if_match {
            if want.0.is_empty() {
                // "must be absent" semantics.
                req = req.set_if_none_match(Some("*".to_string()));
            } else {
                req = req.if_match(format!("\"{}\"", want.0));
            }
        }
        let resp = req.send().await.map_err(map_err)?;
        let etag = resp
            .e_tag()
            .map(|s| s.trim_matches('"').to_string())
            .unwrap_or_else(|| "0".to_string());
        Ok(Etag(etag))
    }

    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let key = self.full_key(name);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(map_err)?;
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
    fn classify_err_prefers_http_status_over_wording() {
        // Real S3 412s say "At least one of the pre-conditions..." — no
        // "PreconditionFailed" in the message. The status must decide.
        assert!(matches!(
            classify_err(
                Some(412),
                "At least one of the pre-conditions you specified did not hold".into()
            ),
            StorageError::PreconditionFailed
        ));
        assert!(matches!(
            classify_err(Some(404), "The specified key does not exist".into()),
            StorageError::NotFound(_)
        ));
        // Transport errors (no response) fall back to modeled-code matching.
        assert!(matches!(
            classify_err(None, "NoSuchKey: The specified key does not exist".into()),
            StorageError::NotFound(_)
        ));
        assert!(matches!(
            classify_err(None, "connection closed".into()),
            StorageError::Backend(_)
        ));
        // A key name that merely contains "404"/"notfound" must not
        // misclassify a non-404 response.
        assert!(matches!(
            classify_err(Some(500), "error for key backup/page404.html".into()),
            StorageError::Backend(_)
        ));
    }
}

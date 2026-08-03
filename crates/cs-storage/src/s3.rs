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

/// Map any AWS SDK error to a `StorageError` by inspecting the Smithy error
/// code and the underlying HTTP status. Works across all per-operation error
/// enums without naming each one.
fn map_err<E: std::fmt::Display>(e: E) -> StorageError {
    let s = e.to_string();
    // Smithy error codes appear as `NoSuchKey`, `PreconditionFailed`, etc.
    let lower = s.to_ascii_lowercase();
    if lower.contains("nosuchkey") || lower.contains("nosuchbucket") || lower.contains("404") {
        return StorageError::NotFound(s);
    }
    if lower.contains("preconditionfailed") || lower.contains("412") {
        return StorageError::PreconditionFailed;
    }
    StorageError::Backend(s)
}

#[async_trait]
impl RemoteStore for S3Store {
    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let full = self.full_key(prefix);
        let mut out = Vec::new();
        let mut cont: Option<String> = None;
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full);
            if let Some(c) = cont {
                req = req.continuation_token(c);
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
                    cont = resp.next_continuation_token().map(|s| s.to_string());
                    if cont.is_none() {
                        break;
                    }
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
        let body = resp.body.collect().await.map_err(map_err)?;
        Ok(body.into_bytes())
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
        let body = resp.body.collect().await.map_err(map_err)?;
        Ok(body.into_bytes())
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

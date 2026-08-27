//! Shared hardening helpers for the HTTP-backed stores (WebDAV, Google Drive,
//! Proton Drive, OneDrive).
//!
//! Threat model: the remote server is untrusted. These helpers enforce
//! - a hard cap on response-body sizes (a hostile server must not be able to
//!   buffer an unbounded "blob" or listing into memory), and
//! - a same-origin redirect policy (a redirect may not change scheme, host,
//!   or port — blocking the https→http downgrade that would re-send the
//!   bearer token in cleartext to a MITM).

use crate::StorageError;
use bytes::Bytes;

/// Maximum response body we will buffer (blobs are file-sized ciphertext;
/// anything larger is a hostile or broken server).
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Error bodies are embedded in `StorageError::Backend` strings (and likely
/// logged); keep them small.
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

/// Read a response body into memory, enforcing `cap` even when the server
/// lies about (or omits) Content-Length.
pub async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<Bytes, StorageError> {
    if let Some(len) = resp.content_length() {
        if len as usize > cap {
            return Err(StorageError::Backend(format!(
                "response body of {len} bytes exceeds the {cap}-byte cap"
            )));
        }
    }
    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| StorageError::Backend(format!("read body: {e}")))?
    {
        if out.len() + chunk.len() > cap {
            return Err(StorageError::Backend(format!(
                "response body exceeds the {cap}-byte cap"
            )));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// Read an error-response body (truncated) for embedding in an error.
pub async fn read_error_body(resp: reqwest::Response) -> String {
    read_body_capped(resp, MAX_ERROR_BODY_BYTES)
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Redirect policy that only follows redirects within the same origin
/// (identical scheme, host, and port). Blocks cross-origin hops and, most
/// importantly, same-host https→http downgrades that would leak the bearer
/// token in cleartext.
pub fn same_origin_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        let same_origin = attempt
            .previous()
            .first()
            .map(|orig| {
                orig.scheme() == attempt.url().scheme()
                    && orig.host() == attempt.url().host()
                    && orig.port() == attempt.url().port()
            })
            .unwrap_or(false);
        if same_origin {
            attempt.follow()
        } else {
            attempt.error("redirect would leave the origin (scheme/host/port change)")
        }
    })
}

/// Build a bearer-token-authenticated client with the hardened redirect
/// policy. Fails loudly on an unusable token or client construction instead
/// of silently continuing unauthenticated.
#[cfg(any(feature = "gdrive", feature = "proton", feature = "onedrive"))]
pub fn authed_client(bearer_token: &str) -> Result<reqwest::Client, StorageError> {
    let mut headers = reqwest::header::HeaderMap::new();
    let value = reqwest::header::HeaderValue::from_str(&format!("Bearer {bearer_token}"))
        .map_err(|e| StorageError::Backend(format!("invalid bearer token: {e}")))?;
    headers.insert(reqwest::header::AUTHORIZATION, value);
    reqwest::Client::builder()
        .default_headers(headers)
        .redirect(same_origin_policy())
        .build()
        .map_err(|e| StorageError::Backend(format!("http client build: {e}")))
}

/// Read and parse a JSON response body under the size cap.
#[cfg(any(feature = "gdrive", feature = "proton", feature = "onedrive"))]
pub async fn read_json_capped<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, StorageError> {
    let body = read_body_capped(resp, MAX_RESPONSE_BYTES).await?;
    serde_json::from_slice(&body).map_err(|e| StorageError::Backend(format!("bad json: {e}")))
}

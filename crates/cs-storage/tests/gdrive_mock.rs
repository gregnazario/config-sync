//! End-to-end Google Drive backend test against an in-process mock of the
//! Drive REST API.
//!
//! The mock implements just the endpoints `GoogleDriveStore` uses:
//! - `GET /drive/v3/files?q=...`        (find the index file)
//! - `POST /drive/v3/files?uploadType=multipart` (create a file)
//! - `PATCH /upload/drive/v3/files/{id}?uploadType=media` (overwrite content)
//! - `GET /drive/v3/files/{id}?alt=media` (download, honoring Range)
//! - `DELETE /drive/v3/files/{id}`       (delete)
//!
//! No live Google account is needed; this proves the backend round-trips real
//! HTTP and honors conditional writes via the index-as-coordination-object.

#![cfg(feature = "gdrive")]

use bytes::Bytes;
use cs_storage::{Etag, GoogleDriveStore, RemoteStore, StorageError};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Default)]
struct Drive {
    // file_id -> bytes
    files: BTreeMap<String, Vec<u8>>,
    next_id: u64,
}

async fn handle(
    drive: Arc<Mutex<Drive>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();

    // GET /drive/v3/files?q=...  -> find index
    if method == Method::GET && path == "/drive/v3/files" && query.contains("_cs_index.json") {
        let d = drive.lock().unwrap();
        let id = d
            .files
            .iter()
            .find(|(_, b)| is_index(b))
            .map(|(id, _)| id.clone());
        let body = match id {
            Some(id) => format!(r#"{{"files":[{{"id":"{id}"}}]}}"#),
            None => r#"{"files":[]}"#.to_string(),
        };
        return Ok(json_resp(StatusCode::OK, &body));
    }

    // POST /drive/v3/files?uploadType=multipart -> create file (parse name + media from multipart)
    if method == Method::POST && path == "/drive/v3/files" && query.contains("uploadType=multipart")
    {
        let ct = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = req
            .into_body()
            .collect()
            .await
            .ok()
            .map(|b| b.to_bytes())
            .unwrap_or_default();
        let (name, media) = parse_multipart(&body, &ct);
        let mut d = drive.lock().unwrap();
        d.next_id += 1;
        let id = format!("file{}", d.next_id);
        d.files.insert(id.clone(), media.unwrap_or_default());
        let body = format!(r#"{{"id":"{id}","name":"{}"}}"#, name.unwrap_or_default());
        return Ok(json_resp(StatusCode::OK, &body));
    }

    // PATCH .../upload/files/{id}?uploadType=media -> replace content
    if method == Method::PATCH {
        if let Some(id) = path.rsplit("/files/").next() {
            let id = id.trim_end_matches('?');
            let body = req
                .into_body()
                .collect()
                .await
                .ok()
                .map(|b| b.to_bytes())
                .unwrap_or_default();
            let mut d = drive.lock().unwrap();
            if d.files.contains_key(id) {
                d.files.insert(id.to_string(), body.to_vec());
                return Ok(json_resp(StatusCode::OK, r#"{"id":"ok"}"#));
            }
        }
        return Ok(resp(StatusCode::NOT_FOUND, b"no such file"));
    }

    // GET /drive/v3/files/{id}?alt=media -> download (honor Range)
    if method == Method::GET {
        if let Some(rest) = path.strip_prefix("/drive/v3/files/") {
            let id = rest;
            let range = req
                .headers()
                .get(hyper::header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let d = drive.lock().unwrap();
            if let Some(b) = d.files.get(id).cloned() {
                if let Some(r) = range.as_deref().and_then(|s| s.strip_prefix("bytes=")) {
                    let parts: Vec<&str> = r.splitn(2, '-').collect();
                    let start = parts
                        .first()
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    let end = parts
                        .get(1)
                        .and_then(|s| s.parse::<usize>().ok())
                        .map(|e| e + 1)
                        .unwrap_or(b.len());
                    let end = std::cmp::min(end, b.len());
                    if start >= b.len() {
                        return Ok(resp(StatusCode::RANGE_NOT_SATISFIABLE, b""));
                    }
                    return Ok(Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .body(Full::new(Bytes::from(b[start..end].to_vec())))
                        .unwrap());
                }
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .body(Full::new(Bytes::from(b)))
                    .unwrap());
            }
            return Ok(resp(StatusCode::NOT_FOUND, b"no such file"));
        }
    }

    // DELETE /drive/v3/files/{id}
    if method == Method::DELETE {
        if let Some(id) = path.strip_prefix("/drive/v3/files/") {
            let mut d = drive.lock().unwrap();
            if d.files.remove(id).is_some() {
                return Ok(resp(StatusCode::NO_CONTENT, b""));
            }
        }
        return Ok(resp(StatusCode::NOT_FOUND, b"no such file"));
    }

    Ok(resp(StatusCode::METHOD_NOT_ALLOWED, b"method not allowed"))
}

fn is_index(b: &[u8]) -> bool {
    // The index json contains an "index_file_id" field; cheap heuristic.
    std::str::from_utf8(b)
        .map(|s| s.contains("\"index_file_id\""))
        .unwrap_or(false)
}

fn parse_multipart(body: &[u8], content_type: &str) -> (Option<String>, Option<Vec<u8>>) {
    // Minimal multipart/form-data parser: split on the boundary, find the part
    // whose content-disposition name is "metadata" (json with name) and the
    // part named "media" (raw bytes).
    let boundary = content_type
        .split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix("boundary="))
        .map(|s| s.to_string());
    let boundary = match boundary {
        Some(b) => b,
        None => return (None, None),
    };
    let sep = format!("--{boundary}");
    let mut name = None;
    let mut media = None;
    let text = String::from_utf8_lossy(body);
    for raw in text.split(&sep) {
        let raw = raw.trim_start_matches("\r\n");
        if raw.is_empty() || raw == "--" {
            continue;
        }
        // Split headers / body at the first blank line.
        let (headers, body_part) = match raw.split_once("\r\n\r\n") {
            Some(x) => x,
            None => continue,
        };
        if headers.contains("name=\"metadata\"") {
            // body_part is JSON like {"name":"...","parents":[...]}
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(body_part) {
                name = v
                    .get("name")
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());
            }
        } else if headers.contains("name=\"media\"") {
            // body_part may have a trailing CRLF before the next boundary.
            let b = body_part.trim_end_matches("\r\n");
            media = Some(b.as_bytes().to_vec());
        }
    }
    (name, media)
}

fn resp(status: StatusCode, body: &[u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_vec())))
        .unwrap()
}

fn json_resp(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

async fn spawn() -> String {
    let drive = Arc::new(Mutex::new(Drive {
        files: BTreeMap::new(),
        next_id: 0,
    }));
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let local = listener.local_addr().unwrap();
    let drive_cloned = drive.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let drive = drive_cloned.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let drive = drive.clone();
                            async move { handle(drive, req).await }
                        }),
                    )
                    .await;
            });
        }
    });
    format!("http://{local}")
}

fn make_store(base_url: &str) -> GoogleDriveStore {
    GoogleDriveStore::new("test-token", "root-folder-id")
        .with_api_base(format!("{base_url}/drive/v3"))
}

#[tokio::test]
async fn put_get_list_delete_round_trips_against_mock_drive() {
    let url = spawn().await;
    let s = make_store(&url);

    let e1 = s
        .put("blobs/abc", Bytes::from_static(b"hello drive"), None)
        .await
        .unwrap();
    assert_eq!(e1.0, "1", "first put bumps index version to 1");
    assert_eq!(
        s.get("blobs/abc").await.unwrap(),
        Bytes::from_static(b"hello drive")
    );

    let names: Vec<_> = s
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert!(names.contains(&"blobs/abc".to_string()));
    assert!(
        !names.contains(&"_cs_index.json".to_string()),
        "index file is hidden from list"
    );

    s.delete("blobs/abc").await.unwrap();
    assert!(matches!(
        s.get("blobs/abc").await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
async fn conditional_put_detects_concurrent_write_against_mock_drive() {
    let url = spawn().await;
    let s = make_store(&url);

    let _e1 = s
        .put("manifest.json", Bytes::from_static(b"v1"), None)
        .await
        .unwrap();
    let _e2 = s
        .put("manifest.json", Bytes::from_static(b"v2"), None)
        .await
        .unwrap();
    // A stale If-Match referencing the first version must be rejected.
    let stale = Etag("1".to_string());
    let r = s
        .put("manifest.json", Bytes::from_static(b"v3"), Some(&stale))
        .await;
    assert!(
        matches!(r, Err(StorageError::PreconditionFailed)),
        "stale conditional put must be rejected, got {r:?}"
    );
}

#[tokio::test]
async fn get_range_returns_subset_against_mock_drive() {
    let url = spawn().await;
    let s = make_store(&url);
    s.put("blob", Bytes::from_static(b"hello drive"), None)
        .await
        .unwrap();
    let sub = s.get_range("blob", 0..5).await.unwrap();
    assert_eq!(sub, Bytes::from_static(b"hello"));
}

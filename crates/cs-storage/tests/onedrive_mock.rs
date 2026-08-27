//! End-to-end OneDrive backend test against an in-process mock of the
//! Microsoft Graph API (OneDrive shape).
//!
//! The mock implements the Graph endpoints OneDriveStore uses:
//! - `PUT /me/drive/root:/<path>:/content` (create/replace, honoring If-Match)
//! - `GET  /me/drive/root:/<path>:/content` (download, honoring Range)
//! - `GET  /me/drive/root:/<prefix>:/children` (list)
//! - `DELETE /me/drive/root:/<path>` (delete)
//!
//! No live Microsoft account is needed; this proves the backend round-trips
//! real HTTP and honors conditional writes.

#![cfg(feature = "onedrive")]

use bytes::Bytes;
use cs_storage::{Etag, OneDriveStore, RemoteStore, StorageError};
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
struct Graph {
    // path -> (etag_version, bytes-as-string)
    items: BTreeMap<String, (u64, String)>,
}

/// Build the Graph `{"value":[...]}` children-list JSON for items under `prefix`.
/// Matches the RemoteStore contract (prefix substring), not Graph's direct-
/// children semantics, so the mock is faithful to how the engine uses list.
fn build_children_json(g: &Graph, prefix: &str) -> String {
    let mut items = String::from(r#"{"value":["#);
    let mut first = true;
    for (name, (_, content)) in &g.items {
        if name.starts_with(prefix) {
            // Return the full logical name (not just the basename) so the
            // engine sees prefix-matching RemoteStore semantics.
            if !first {
                items.push(',');
            }
            items.push_str(&format!(
                r#"{{"name":"{name}","eTag":"\"x\"","size":{}}}"#,
                content.len()
            ));
            first = false;
        }
    }
    items.push_str("]}");
    items
}

async fn handle(
    graph: Arc<Mutex<Graph>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let if_match = req.headers().get(hyper::header::IF_MATCH).cloned();
    let range = req
        .headers()
        .get(hyper::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Parse the Graph path-addressed segments: /me/drive/root:/<item>:/content
    // or /me/drive/root:/<item> or /me/drive/root:/<prefix>:/children
    let root = "/me/drive/root:/";
    let Some(rest) = path.strip_prefix(root) else {
        return Ok(resp(StatusCode::NOT_FOUND, b"not a drive path"));
    };

    // content endpoint
    if let Some(item_path) = rest.strip_suffix(":/content") {
        let name = url_decode(item_path);
        match method {
            Method::GET => {
                let g = graph.lock().unwrap();
                match g.items.get(&name) {
                    Some((_, content)) => {
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
                                .unwrap_or(content.len());
                            let end = std::cmp::min(end, content.len());
                            if start >= content.len() {
                                return Ok(resp(StatusCode::RANGE_NOT_SATISFIABLE, b""));
                            }
                            return Ok(Response::builder()
                                .status(StatusCode::PARTIAL_CONTENT)
                                .body(Full::new(Bytes::from(
                                    content.as_bytes()[start..end].to_vec(),
                                )))
                                .unwrap());
                        }
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(content.clone())))
                            .unwrap())
                    }
                    None => Ok(resp(StatusCode::NOT_FOUND, b"not found")),
                }
            }
            Method::PUT => {
                let body = req
                    .into_body()
                    .collect()
                    .await
                    .ok()
                    .map(|b| b.to_bytes())
                    .unwrap_or_default();
                let text = String::from_utf8_lossy(&body).to_string();
                let mut g = graph.lock().unwrap();
                if let Some(im) = if_match {
                    let want = im.to_str().unwrap_or("").trim_matches('"');
                    let cur = g.items.get(&name).map(|(v, _)| v.to_string());
                    match cur {
                        Some(c) if c == want => {}
                        _ => return Ok(resp(StatusCode::PRECONDITION_FAILED, b"etag mismatch")),
                    }
                }
                let next = g.items.get(&name).map(|(v, _)| v + 1).unwrap_or(1);
                g.items.insert(name.clone(), (next, text));
                Ok(json_resp(
                    StatusCode::OK,
                    &format!(r#"{{"name":"{name}","eTag":"\"{next}\"","size":0}}"#),
                ))
            }
            _ => Ok(resp(StatusCode::METHOD_NOT_ALLOWED, b"method not allowed")),
        }
    } else if let Some(prefix_path) = rest.strip_suffix(":/children") {
        // list children of a prefix folder
        let prefix = url_decode(prefix_path);
        let g = graph.lock().unwrap();
        let items = build_children_json(&g, &prefix);
        Ok(json_resp(StatusCode::OK, &items))
    } else if rest == "children" {
        // list children of root (empty prefix)
        let g = graph.lock().unwrap();
        let items = build_children_json(&g, "");
        Ok(json_resp(StatusCode::OK, &items))
    } else {
        // item endpoint (DELETE)
        let name = url_decode(rest);
        if method == Method::DELETE {
            let mut g = graph.lock().unwrap();
            if g.items.remove(&name).is_some() {
                Ok(resp(StatusCode::NO_CONTENT, b""))
            } else {
                Ok(resp(StatusCode::NOT_FOUND, b"not found"))
            }
        } else {
            Ok(resp(StatusCode::METHOD_NOT_ALLOWED, b"method not allowed"))
        }
    }
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

async fn spawn() -> String {
    let graph = Arc::new(Mutex::new(Graph::default()));
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let local = listener.local_addr().unwrap();
    let graph_cloned = graph.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let graph = graph_cloned.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let graph = graph.clone();
                            async move { handle(graph, req).await }
                        }),
                    )
                    .await;
            });
        }
    });
    format!("http://{local}")
}

fn make_store(base_url: &str) -> OneDriveStore {
    OneDriveStore::with_base_and_token("test-oauth-token", base_url).unwrap()
}

#[tokio::test]
async fn put_get_list_delete_round_trips_against_mock_onedrive() {
    let url = spawn().await;
    let s = make_store(&url);

    let e1 = s
        .put("blobs/abc", Bytes::from_static(b"hello onedrive"), None)
        .await
        .unwrap();
    assert!(!e1.0.is_empty(), "put returns an etag");
    assert_eq!(
        s.get("blobs/abc").await.unwrap(),
        Bytes::from_static(b"hello onedrive")
    );

    let names: Vec<_> = s
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert!(
        names.contains(&"blobs/abc".to_string()),
        "list includes the object"
    );

    s.delete("blobs/abc").await.unwrap();
    assert!(matches!(
        s.get("blobs/abc").await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
async fn conditional_put_detects_concurrent_write_against_mock_onedrive() {
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
    // A stale If-Match referencing version 1 must be rejected.
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
async fn get_range_returns_subset_against_mock_onedrive() {
    let url = spawn().await;
    let s = make_store(&url);
    s.put("blob", Bytes::from_static(b"hello onedrive"), None)
        .await
        .unwrap();
    let sub = s.get_range("blob", 0..5).await.unwrap();
    assert_eq!(sub, Bytes::from_static(b"hello"));
}

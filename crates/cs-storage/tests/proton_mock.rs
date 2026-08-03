//! End-to-end Proton Drive backend test against an in-process mock of Proton's
//! HTTP gateway shape (path-addressed nodes with per-node revisions and
//! `If-Match` conditional writes).
//!
//! No live Proton account is needed; this proves `ProtonDriveStore` round-trips
//! real HTTP and honors conditional writes.

#![cfg(feature = "proton")]

use bytes::Bytes;
use cs_storage::{Etag, ProtonDriveStore, RemoteStore, StorageError};
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
struct Gateway {
    // path -> (revision, bytes-as-string)
    nodes: BTreeMap<String, (u64, String)>,
}

async fn handle(
    gw: Arc<Mutex<Gateway>>,
    base: String,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let if_match = req.headers().get(hyper::header::IF_MATCH).cloned();
    let nodes_prefix = format!("/{base}/nodes");

    // GET /nodes?prefix=...  -> list
    if method == Method::GET && path == nodes_prefix {
        let prefix = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find(|p| p.starts_with("prefix=")))
            .and_then(|p| p.strip_prefix("prefix="))
            .map(url_decode)
            .unwrap_or_default();
        let gw = gw.lock().unwrap();
        let mut out = String::from(r#"{"nodes":["#);
        let mut first = true;
        for (name, (rev, content)) in &gw.nodes {
            if name.starts_with(&prefix) {
                if !first {
                    out.push(',');
                }
                out.push_str(&format!(
                    r#"{{"name":"{name}","revision":{rev},"size":{}}}"#,
                    content.len()
                ));
                first = false;
            }
        }
        out.push_str("]}");
        return Ok(json_resp(StatusCode::OK, &out));
    }

    // Path-addressed node operations: /nodes/<name...>
    let name = match path.strip_prefix(&format!("{nodes_prefix}/")) {
        Some(n) => url_decode(n),
        None => return Ok(resp(StatusCode::NOT_FOUND, b"no node")),
    };

    match method {
        Method::GET => {
            let gw = gw.lock().unwrap();
            match gw.nodes.get(&name) {
                Some((rev, content)) => Ok(json_resp(
                    StatusCode::OK,
                    &format!(
                        r#"{{"revision":{rev},"content":{}}}"#,
                        serde_json::Value::String(content.clone())
                    ),
                )),
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
            let mut gw = gw.lock().unwrap();
            if let Some(im) = if_match {
                let want = im.to_str().unwrap_or("");
                let cur = gw.nodes.get(&name).map(|(r, _)| r.to_string());
                match cur {
                    Some(c) if c == want => {}
                    _ => return Ok(resp(StatusCode::PRECONDITION_FAILED, b"revision mismatch")),
                }
            }
            let next = gw.nodes.get(&name).map(|(r, _)| r + 1).unwrap_or(1);
            gw.nodes.insert(name.clone(), (next, text));
            Ok(json_resp(
                StatusCode::OK,
                &format!(r#"{{"revision":{next}}}"#),
            ))
        }
        Method::DELETE => {
            let mut gw = gw.lock().unwrap();
            if gw.nodes.remove(&name).is_some() {
                Ok(resp(StatusCode::NO_CONTENT, b""))
            } else {
                Ok(resp(StatusCode::NOT_FOUND, b"not found"))
            }
        }
        _ => Ok(resp(StatusCode::METHOD_NOT_ALLOWED, b"method not allowed")),
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
    let gw = Arc::new(Mutex::new(Gateway::default()));
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let local = listener.local_addr().unwrap();
    let gw_cloned = gw.clone();
    let base = "drive".to_string();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let gw = gw_cloned.clone();
            let base = base.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let gw = gw.clone();
                            let base = base.clone();
                            async move { handle(gw, base, req).await }
                        }),
                    )
                    .await;
            });
        }
    });
    format!("http://{local}/drive")
}

fn make_store(base_url: &str) -> ProtonDriveStore {
    ProtonDriveStore::new("test-session-token", base_url)
}

#[tokio::test]
async fn put_get_list_delete_round_trips_against_mock_proton() {
    let url = spawn().await;
    let s = make_store(&url);

    let e1 = s
        .put("blobs/abc", Bytes::from_static(b"hello proton"), None)
        .await
        .unwrap();
    assert_eq!(e1.0, "1", "first put returns revision 1");
    assert_eq!(
        s.get("blobs/abc").await.unwrap(),
        Bytes::from_static(b"hello proton")
    );

    let names: Vec<_> = s
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert!(names.contains(&"blobs/abc".to_string()));

    s.delete("blobs/abc").await.unwrap();
    assert!(matches!(
        s.get("blobs/abc").await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
async fn conditional_put_detects_concurrent_write_against_mock_proton() {
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
    // A stale If-Match referencing revision 1 must be rejected (current is 2).
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
async fn get_range_returns_subset_against_mock_proton() {
    let url = spawn().await;
    let s = make_store(&url);
    s.put("blob", Bytes::from_static(b"hello proton"), None)
        .await
        .unwrap();
    let sub = s.get_range("blob", 0..5).await.unwrap();
    assert_eq!(sub, Bytes::from_static(b"hello"));
}

#[tokio::test]
async fn list_with_prefix_filters_nodes() {
    let url = spawn().await;
    let s = make_store(&url);
    s.put("blobs/aaa", Bytes::from_static(b"x"), None)
        .await
        .unwrap();
    s.put("blobs/bbb", Bytes::from_static(b"y"), None)
        .await
        .unwrap();
    s.put("manifest.json", Bytes::from_static(b"{}"), None)
        .await
        .unwrap();
    let names: Vec<_> = s
        .list("blobs/")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"blobs/aaa".to_string()));
    assert!(names.contains(&"blobs/bbb".to_string()));
}

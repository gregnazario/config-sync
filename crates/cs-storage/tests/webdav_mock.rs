//! End-to-end WebDAV backend test against an in-process HTTP server.
//!
//! The server implements just the WebDAV subset config-sync uses (PUT/GET/
//! DELETE/PROPFIND Depth:1 + `If-Match`/`If-None-Match`), backed by an
//! in-memory map. This proves `WebDavStore` round-trips real HTTP and honors
//! conditional writes — without needing a live Nextcloud/ownCloud/iCloud.

#![cfg(feature = "webdav")]

use bytes::Bytes;
use cs_storage::{Etag, RemoteStore, StorageError, WebDavStore};
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
struct Store {
    // path -> (etag_counter, bytes)
    files: BTreeMap<String, (u64, Vec<u8>)>,
}

async fn handle(
    store: Arc<Mutex<Store>>,
    base: String,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let method = req.method().clone();
    let path = req
        .uri()
        .path()
        .trim_start_matches(&format!("/{base}"))
        .trim_start_matches('/')
        .to_string();

    // Conditional headers.
    let if_match = req.headers().get(hyper::header::IF_MATCH).cloned();
    let if_none_match = req.headers().get(hyper::header::IF_NONE_MATCH).cloned();

    match method {
        Method::PUT => {
            let body = req.into_body().collect().await.ok().map(|b| b.to_bytes());
            let bytes = body.unwrap_or_default();
            let mut st = store.lock().unwrap();
            if let Some(im) = if_match {
                let want = im.to_str().unwrap_or("").trim_matches('"');
                let cur = st.files.get(&path).map(|(v, _)| *v);
                match cur {
                    Some(v) if want == v.to_string() => {}
                    _ => return Ok(resp(StatusCode::PRECONDITION_FAILED, b"etag mismatch")),
                }
            }
            if let Some(inm) = if_none_match {
                if inm.to_str().unwrap_or("") == "*" && st.files.contains_key(&path) {
                    return Ok(resp(StatusCode::PRECONDITION_FAILED, b"exists"));
                }
            }
            let next = st.files.get(&path).map(|(v, _)| v + 1).unwrap_or(1);
            st.files.insert(path.clone(), (next, bytes.to_vec()));
            Ok(etag_resp(StatusCode::OK, next))
        }
        Method::GET => {
            // Optional Range support so get_range round-trips realistically.
            let range_hdr = req
                .headers()
                .get(hyper::header::RANGE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let st = store.lock().unwrap();
            match st.files.get(&path) {
                Some((_, b)) => {
                    if let Some(r) = range_hdr.as_deref().and_then(|s| s.strip_prefix("bytes=")) {
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
                            return Ok(Response::builder()
                                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                                .body(Full::new(Bytes::new()))
                                .unwrap());
                        }
                        Ok(Response::builder()
                            .status(StatusCode::PARTIAL_CONTENT)
                            .body(Full::new(Bytes::from(b[start..end].to_vec())))
                            .unwrap())
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(b.clone())))
                            .unwrap())
                    }
                }
                None => Ok(resp(StatusCode::NOT_FOUND, b"not found")),
            }
        }
        Method::DELETE => {
            let mut st = store.lock().unwrap();
            if st.files.remove(&path).is_some() {
                Ok(resp(StatusCode::NO_CONTENT, b""))
            } else {
                Ok(resp(StatusCode::NOT_FOUND, b"not found"))
            }
        }
        // PROPFIND: return a multistatus with one response per file under path.
        m if m.as_str() == "PROPFIND" => {
            let st = store.lock().unwrap();
            let mut xml = String::from(r#"<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">"#);
            for (k, (v, b)) in &st.files {
                if k.starts_with(&path) {
                    xml.push_str(&format!(
                        "<D:response><D:href>/{base}/{k}</D:href>\
                         <D:propstat><D:prop>\
                         <D:getetag>\"{v}\"</D:getetag>\
                         <D:getcontentlength>{}</D:getcontentlength>\
                         </D:prop></D:propstat></D:response>",
                        b.len()
                    ));
                }
            }
            xml.push_str("</D:multistatus>");
            Ok(Response::builder()
                .status(StatusCode::MULTI_STATUS)
                .header("content-type", "application/xml")
                .body(Full::new(Bytes::from(xml)))
                .unwrap())
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

fn etag_resp(status: StatusCode, version: u64) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::ETAG, format!("\"{version}\""))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Spawn an in-process WebDAV-style HTTP server on an ephemeral port and return
/// its base URL plus the shared store (for assertions).
async fn spawn() -> (String, Arc<Mutex<Store>>) {
    let store = Arc::new(Mutex::new(Store::default()));
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();
    let local = listener.local_addr().unwrap();
    let store_cloned = store.clone();
    let base = "config-sync".to_string();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let store = store_cloned.clone();
            let base = base.clone();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let store = store.clone();
                            let base = base.clone();
                            async move { handle(store, base, req).await }
                        }),
                    )
                    .await;
            });
        }
    });
    (format!("http://{local}/config-sync/"), store)
}

fn make_store(base_url: &str) -> WebDavStore {
    let http = reqwest::Client::builder().build().unwrap();
    WebDavStore::new(http, base_url).unwrap()
}

#[tokio::test]
async fn put_get_list_delete_round_trips_over_http() {
    let (url, _store) = spawn().await;
    let s = make_store(&url);

    let e1 = s
        .put("blobs/abc", Bytes::from_static(b"hello"), None)
        .await
        .unwrap();
    assert!(!e1.0.is_empty(), "server returned an etag");
    assert_eq!(
        s.get("blobs/abc").await.unwrap(),
        Bytes::from_static(b"hello")
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
        "list returned the object"
    );

    s.delete("blobs/abc").await.unwrap();
    assert!(matches!(
        s.get("blobs/abc").await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
async fn conditional_put_detects_concurrent_write_over_http() {
    let (url, _store) = spawn().await;
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
async fn get_range_returns_subset_over_http() {
    let (url, _store) = spawn().await;
    let s = make_store(&url);
    s.put("blob", Bytes::from_static(b"hello world"), None)
        .await
        .unwrap();
    let sub = s.get_range("blob", 0..5).await.unwrap();
    assert_eq!(sub, Bytes::from_static(b"hello"));
}

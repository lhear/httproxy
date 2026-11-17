mod runtime;
mod sys;

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use http::StatusCode;
use std::ffi::{CStr, CString};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tracing::warn;

use runtime::{Event, Executor, Spec, next_key};
use sys::Ptr;

fn engine_version(engine: Ptr) -> Result<String> {
    let raw = sys::api().engine_version(engine);
    if raw.is_null() {
        bail!("cronet: engine reported no version");
    }
    Ok(unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned())
}

fn build_user_agent(version: &str) -> Option<CString> {
    let major = version.split('.').next()?;
    if major.is_empty() || !major.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    CString::new(format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
    ))
    .ok()
}

pub struct Client {
    exec: Arc<Executor>,
}

impl Client {
    pub fn new(resolve: Option<&str>) -> Result<Arc<Self>> {
        sys::load().map_err(|error| anyhow!(error))?;
        let engine = Arc::new(Engine::start(resolve)?);
        let callback = Arc::new(Callback::new()?);
        let exec = Executor::new(Arc::clone(&engine), Arc::clone(&callback))?;
        Ok(Arc::new(Self { exec }))
    }

    pub fn post(&self, url: &str) -> RequestBuilder {
        self.request("POST", url)
    }

    fn request(&self, method: &'static str, url: &str) -> RequestBuilder {
        RequestBuilder {
            exec: Arc::clone(&self.exec),
            spec: Spec {
                url: url.to_owned(),
                method,
                headers: Vec::new(),
                body: None,
            },
        }
    }
}

pub(crate) struct Engine(Ptr, AtomicBool);

impl Engine {
    fn start(resolve: Option<&str>) -> Result<Self> {
        let options = resolve.map(experimental_options).transpose()?;
        let api = sys::api();
        let engine = api.engine_create();
        if engine.is_null() {
            bail!("cronet: engine create failed");
        }
        let version = engine_version(engine).inspect_err(|_| api.engine_destroy(engine))?;
        let Some(user_agent) = build_user_agent(&version) else {
            api.engine_destroy(engine);
            bail!("cronet: cannot derive a user agent from version {version}");
        };
        let params = api.engine_params_create();
        if params.is_null() {
            api.engine_destroy(engine);
            bail!("cronet: engine params create failed");
        }
        api.engine_params_quic(params, true);
        api.engine_params_http2(params, true);
        api.engine_params_brotli(params, true);
        api.engine_params_cache_mode(params, sys::HTTP_CACHE_DISABLED);
        api.engine_params_user_agent(params, user_agent.as_ptr());
        if let Some(options) = options {
            api.engine_params_experimental(params, options.as_ptr());
        }
        if let Err(error) = install_root_store(api, engine) {
            warn!(%error, "cronet: falling back to Chromium's root store");
        }
        let result = api.engine_start(engine, params);
        api.engine_params_destroy(params);
        if result != sys::RESULT_SUCCESS {
            api.engine_destroy(engine);
            bail!("cronet: engine start failed ({result})");
        }
        Ok(Self(engine, AtomicBool::new(false)))
    }

    pub(crate) fn shutdown(&self) {
        if !self.1.swap(true, Ordering::AcqRel) {
            let _ = sys::api().engine_shutdown(self.0);
        }
    }
}

fn install_root_store(api: &sys::Api, engine: Ptr) -> Result<()> {
    let pem = CString::new(root_store_pem())
        .map_err(|_| anyhow!("cronet: root store holds a nul byte"))?;
    let verifier = api.cert_verifier_create(pem.as_ptr());
    if verifier.is_null() {
        bail!("cronet: the loaded library rejected the Mozilla root store");
    }
    api.engine_cert_verifier(engine, verifier);
    Ok(())
}

fn root_store_pem() -> Vec<u8> {
    const WIDTH: usize = 64;
    let mut out = Vec::with_capacity(512 * 1024);
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        out.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        let encoded = BASE64.encode(cert.as_ref());
        for line in encoded.as_bytes().chunks(WIDTH) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
        out.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    out
}

fn experimental_options(address: &str) -> Result<CString> {
    let address = if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]")
    } else {
        address.to_owned()
    };
    let options = format!(r#"{{"HostResolverRules":{{"host_resolver_rules":"MAP * {address}"}}}}"#);
    CString::new(options).map_err(|_| anyhow!("cronet: invalid resolver address"))
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
        sys::api().engine_destroy(self.0);
    }
}

struct Callback(Ptr);

impl Callback {
    fn new() -> Result<Self> {
        let callback = sys::api().callback_create(
            Some(runtime::on_redirect),
            Some(runtime::on_response_started),
            Some(runtime::on_read_completed),
            Some(runtime::on_succeeded),
            Some(runtime::on_failed),
            Some(runtime::on_canceled),
        );
        if callback.is_null() {
            bail!("cronet: callback create failed");
        }
        Ok(Self(callback))
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        sys::api().callback_destroy(self.0);
    }
}

pub struct RequestBuilder {
    exec: Arc<Executor>,
    spec: Spec,
}

impl RequestBuilder {
    pub fn header(mut self, name: &str, value: impl AsRef<str>) -> Self {
        self.spec
            .headers
            .push((name.to_owned(), value.as_ref().to_owned()));
        self
    }

    pub fn body(mut self, body: Bytes) -> Self {
        self.spec.body = Some(body);
        self
    }

    pub async fn send(self) -> Result<Response> {
        url::Url::parse(&self.spec.url).context("invalid request url")?;

        let key = next_key();
        let (events, inbox) = mpsc::unbounded_channel();
        self.exec.open(key, events, self.spec);

        let mut guard = CloseGuard {
            exec: Arc::clone(&self.exec),
            key,
            armed: true,
        };
        let mut inbox = inbox;
        loop {
            match inbox.recv().await {
                Some(Event::Status(status)) => {
                    guard.disarm();
                    return Ok(Response {
                        status: StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
                        body: Body {
                            exec: self.exec,
                            key,
                            inbox,
                        },
                    });
                }
                Some(Event::Fail(reason)) => bail!("{reason}"),
                Some(_) => {}
                None => bail!("cronet: request aborted"),
            }
        }
    }
}

struct CloseGuard {
    exec: Arc<Executor>,
    key: usize,
    armed: bool,
}

impl CloseGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CloseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.exec.close(self.key);
        }
    }
}

pub struct Response {
    status: StatusCode,
    body: Body,
}

impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn into_body(self) -> Body {
        self.body
    }

    pub async fn bytes(mut self) -> Result<Bytes> {
        let mut collected = BytesMut::new();
        while let Some(chunk) = self.body.next().await {
            collected.extend_from_slice(&chunk?);
        }
        Ok(collected.freeze())
    }

    pub async fn discard(mut self) -> Result<()> {
        while let Some(chunk) = self.body.next().await {
            chunk?;
        }
        Ok(())
    }
}

pub struct Body {
    exec: Arc<Executor>,
    key: usize,
    inbox: UnboundedReceiver<Event>,
}

impl Stream for Body {
    type Item = Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.inbox.poll_recv(cx) {
                Poll::Ready(Some(Event::Data(chunk))) => {
                    this.exec.resume(this.key);
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Event::Fail(reason))) => {
                    return Poll::Ready(Some(Err(anyhow!(reason))));
                }
                Poll::Ready(Some(Event::Status(_))) => {}
                Poll::Ready(Some(Event::End)) | Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        self.exec.close(self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Weak;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    async fn upstream() -> SocketAddr {
        let router = axum::Router::new().route(
            "/",
            axum::routing::post(|body: Bytes| async move { body.len().to_string() }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        address
    }

    async fn settle(watch: &Weak<runtime::Shared>, live: usize) {
        timeout(Duration::from_secs(10), async {
            while watch.strong_count() > live {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the runtime still owns requests");
    }

    #[test]
    fn derives_the_user_agent_from_the_cronet_version() {
        assert_eq!(
            build_user_agent("154.0.8037.49").unwrap().to_str().unwrap(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
        );
        assert_eq!(
            build_user_agent("120.0.6099.109")
                .unwrap()
                .to_str()
                .unwrap(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        );
        assert!(build_user_agent("").is_none());
        assert!(build_user_agent("Cronet").is_none());
    }

    #[tokio::test]
    async fn sends_the_browser_user_agent() {
        let router = axum::Router::new().route(
            "/",
            axum::routing::post(|headers: http::HeaderMap| async move {
                headers
                    .get(http::header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let client = Client::new(None).unwrap();
        let url = format!("http://{address}/");
        let body = client
            .post(&url)
            .body(Bytes::from_static(b"payload"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        let expected = build_user_agent(&engine_version(client.exec.engine()).unwrap()).unwrap();
        assert_eq!(&body[..], expected.to_bytes());
    }

    #[tokio::test]
    async fn releases_requests_uploads_and_engine() {
        let client = Client::new(None).unwrap();
        let watch = client.exec.watch();
        let live = watch.strong_count();
        let address = upstream().await;
        let url = format!("http://{address}/");

        for _ in 0..8 {
            let response = client
                .post(&url)
                .body(Bytes::from_static(b"payload"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(&response.bytes().await.unwrap()[..], b"7");
            settle(&watch, live).await;
        }

        for _ in 0..4 {
            let response = client
                .post(&url)
                .body(Bytes::from_static(b"payload"))
                .send()
                .await
                .unwrap();
            drop(response);
            settle(&watch, live).await;
        }

        drop(client);
        assert_eq!(
            watch.strong_count(),
            0,
            "cronet runtime outlived the client"
        );
    }

    #[test]
    fn root_store_pem_holds_every_mozilla_root() {
        let pem = String::from_utf8(root_store_pem()).unwrap();
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS.len();
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), roots);
        assert_eq!(pem.matches("-----END CERTIFICATE-----").count(), roots);
    }

    #[tokio::test]
    async fn body_chunks_stay_mutable_after_the_runtime_is_dropped() {
        let client = Client::new(None).unwrap();
        let watch = client.exec.watch();
        let address = upstream().await;
        let mut body = client
            .post(&format!("http://{address}/"))
            .body(Bytes::from_static(b"payload"))
            .send()
            .await
            .unwrap()
            .into_body();
        let chunk = body.next().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"7");
        let pointer = chunk.as_ptr();
        drop(body);
        drop(client);
        assert_eq!(watch.strong_count(), 0);
        let mut writable = chunk
            .try_into_mut()
            .expect("native reads must transfer ownership");
        assert_eq!(writable.as_ptr(), pointer);
        writable[0] = b'8';
        assert_eq!(&writable[..], b"8");
    }
}

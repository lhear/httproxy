use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use bytes::{Buf, Bytes, BytesMut};
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use quinn::{RecvStream, SendStream, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use super::h3;

const MAX_DATA_FRAME: usize = 64 * 1024;

const MAX_RESPONSE_HEAD_BUFFER: usize = 64 * 1024;

const MAX_CONTROL_BUFFER: usize = 64 * 1024;

const QUIC_ALPN: &[u8] = b"h3";

pub(crate) struct MasqueConfig {
    pub sni: String,
    pub connect_timeout: Duration,
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    pub tls: Arc<rustls::ClientConfig>,
}

impl MasqueConfig {
    pub(crate) fn client_config(&self) -> Result<quinn::ClientConfig> {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(self.keepalive));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(self.idle_timeout)
                .context("warp: invalid idle timeout")?,
        ));
        transport.max_concurrent_bidi_streams(VarInt::from_u32(4));
        transport.max_concurrent_uni_streams(VarInt::from_u32(8));
        transport.stream_receive_window(VarInt::from_u32(1 << 20));
        transport.receive_window(VarInt::from_u32(8 << 20));

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::clone(&self.tls))
            .map_err(|e| anyhow!("warp: QUIC TLS config rejected: {e}"))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}

pub(crate) struct MasqueConn {
    conn: quinn::Connection,
    _control: SendStream,
    _qpack_encoder: SendStream,
    _qpack_decoder: SendStream,
    retiring: Arc<AtomicBool>,
    guard: Arc<CloseGuard>,
}

pub(crate) struct CloseGuard {
    conn: quinn::Connection,
}

impl Drop for CloseGuard {
    fn drop(&mut self) {
        self.conn.close(VarInt::from_u32(0), b"reconnect");
    }
}

#[derive(Clone)]
pub(crate) struct KeepAlive {
    _guard: Arc<CloseGuard>,
}

impl KeepAlive {
    fn new(guard: Arc<CloseGuard>) -> Self {
        Self { _guard: guard }
    }
}

#[derive(Debug)]
pub(crate) struct ConnectRejected {
    status: u16,
    authority: String,
}

impl std::fmt::Display for ConnectRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "warp: CONNECT {} rejected with status {}",
            self.authority, self.status
        )
    }
}

impl std::error::Error for ConnectRejected {}

impl MasqueConn {
    pub(crate) async fn establish(
        endpoint: &quinn::Endpoint,
        cfg: &MasqueConfig,
        addr: SocketAddr,
    ) -> Result<Self> {
        let connecting = endpoint
            .connect(addr, &cfg.sni)
            .context("warp: invalid endpoint address")?;

        let conn = tokio::time::timeout(cfg.connect_timeout, connecting)
            .await
            .context("warp: QUIC handshake timed out")?
            .context("warp: QUIC handshake failed")?;

        let mut control = conn.open_uni().await.context("warp: open control stream")?;
        control
            .write_all(&h3::control_stream_bytes())
            .await
            .context("warp: send SETTINGS")?;

        let mut qpack_encoder = conn.open_uni().await.context("warp: open QPACK encoder")?;
        qpack_encoder
            .write_all(&[h3::STREAM_QPACK_ENCODER as u8])
            .await?;
        let mut qpack_decoder = conn.open_uni().await.context("warp: open QPACK decoder")?;
        qpack_decoder
            .write_all(&[h3::STREAM_QPACK_DECODER as u8])
            .await?;

        debug!(endpoint = %addr, "warp: MASQUE connection established");

        let retiring = Arc::new(AtomicBool::new(false));
        tokio::spawn(watch_server_streams(conn.clone(), Arc::clone(&retiring)));

        let guard = Arc::new(CloseGuard { conn: conn.clone() });
        Ok(Self {
            conn,
            _control: control,
            _qpack_encoder: qpack_encoder,
            _qpack_decoder: qpack_decoder,
            retiring,
            guard,
        })
    }

    pub(crate) fn is_usable(&self) -> bool {
        self.conn.close_reason().is_none() && !self.retiring.load(Ordering::Acquire)
    }

    pub(crate) async fn open(&self, authority: &str) -> Result<MasqueStream> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .context("warp: open request stream")?;

        let block = h3::encode_connect_headers(authority);
        let mut frame = BytesMut::with_capacity(block.len() + 12);
        h3::put_varint(&mut frame, h3::FRAME_HEADERS);
        h3::put_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        send.write_all(&frame)
            .await
            .with_context(|| format!("warp: send CONNECT {authority}"))?;

        let (status, pending) = read_response_head(&mut recv, authority).await?;
        if !(200..300).contains(&status) {
            let _ = send.reset(VarInt::from_u32(0));
            let _ = recv.stop(VarInt::from_u32(0));
            return Err(anyhow::Error::new(ConnectRejected {
                status,
                authority: authority.to_string(),
            }));
        }

        Ok(MasqueStream {
            send: MasqueSend::new(send),
            recv: MasqueRecv::new(recv, pending),
            guard: KeepAlive::new(Arc::clone(&self.guard)),
        })
    }
}

pub(crate) struct MasqueStream {
    pub(crate) send: MasqueSend,
    pub(crate) recv: MasqueRecv,
    pub(crate) guard: KeepAlive,
}

impl MasqueStream {
    pub(crate) fn into_io(self) -> DuplexIo {
        let Self { send, recv, guard } = self;
        DuplexIo {
            io: Box::pin(tokio::io::join(recv, send)),
            _guard: guard,
        }
    }
}

trait Duplex: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> Duplex for T {}

pub(crate) struct DuplexIo {
    io: Pin<Box<dyn Duplex + Send>>,
    _guard: KeepAlive,
}

impl AsyncRead for DuplexIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self.get_mut().io.as_mut(), cx, buf)
    }
}

impl AsyncWrite for DuplexIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self.get_mut().io.as_mut(), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self.get_mut().io.as_mut(), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self.get_mut().io.as_mut(), cx)
    }
}

async fn read_response_head(recv: &mut RecvStream, authority: &str) -> Result<(u16, BytesMut)> {
    let mut buf = BytesMut::with_capacity(512);
    loop {
        while let Some((ty, len, used)) = h3::get_frame_header(&buf) {
            let total = used
                .checked_add(usize::try_from(len).unwrap_or(usize::MAX))
                .context("warp: response frame length overflow")?;
            if buf.len() < total {
                if total > MAX_RESPONSE_HEAD_BUFFER {
                    bail!("warp: response frame too large ({total} bytes)");
                }
                break;
            }
            if ty == h3::FRAME_HEADERS {
                let status = h3::decode_status(&buf[used..total])
                    .map_err(|e| anyhow!("warp: unusable CONNECT response for {authority}: {e}"))?;
                return Ok((status, buf.split_off(total)));
            }
            buf.advance(total);
        }

        if buf.len() > MAX_RESPONSE_HEAD_BUFFER {
            bail!(
                "warp: CONNECT response for {authority} exceeded {MAX_RESPONSE_HEAD_BUFFER} bytes"
            );
        }

        match recv
            .read_chunk(4096, true)
            .await
            .context("warp: read response")?
        {
            Some(chunk) => buf.extend_from_slice(&chunk.bytes),
            None => bail!("warp: connection closed before CONNECT response for {authority}"),
        }
    }
}

async fn watch_server_streams(conn: quinn::Connection, retiring: Arc<AtomicBool>) {
    loop {
        let Ok(recv) = conn.accept_uni().await else {
            return;
        };
        let retiring = Arc::clone(&retiring);
        tokio::spawn(async move {
            let _ = watch_server_stream(recv, retiring).await;
        });
    }
}

async fn watch_server_stream(mut recv: RecvStream, retiring: Arc<AtomicBool>) -> Option<()> {
    let mut buf = BytesMut::new();
    let kind = loop {
        if let Some((kind, used)) = h3::get_varint(&buf) {
            buf.advance(used);
            break kind;
        }
        let chunk = recv.read_chunk(4096, true).await.ok()??;
        buf.extend_from_slice(&chunk.bytes);
    };

    if kind != h3::STREAM_CONTROL {
        let _ = tokio::io::copy(&mut recv, &mut tokio::io::sink()).await;
        return Some(());
    }

    loop {
        if control_has_goaway(&mut buf) {
            warn!("warp: gateway sent GOAWAY, connection is retired");
            retiring.store(true, Ordering::Release);
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut recv, &mut tokio::io::sink()).await;
            });
            return Some(());
        }
        if buf.len() > MAX_CONTROL_BUFFER {
            let _ = tokio::io::copy(&mut recv, &mut tokio::io::sink()).await;
            return None;
        }
        let chunk = recv.read_chunk(4096, true).await.ok()??;
        buf.extend_from_slice(&chunk.bytes);
    }
}

fn control_has_goaway(buf: &mut BytesMut) -> bool {
    let mut goaway = false;
    while let Some((kind, len, used)) = h3::get_frame_header(buf) {
        let Ok(len) = usize::try_from(len) else {
            break;
        };
        let Some(total) = used.checked_add(len) else {
            break;
        };
        if buf.len() < total {
            break;
        }
        buf.advance(total);
        if kind == h3::FRAME_GOAWAY {
            goaway = true;
        }
    }
    goaway
}

pub(crate) struct MasqueSend {
    stream: SendStream,
    chunks: Vec<Bytes>,
    finished: bool,
    write: WriteState,
}

#[derive(Default)]
struct WriteState {
    header: [u8; 16],
    header_len: u8,
    header_sent: u8,
    remaining: usize,
}

impl MasqueSend {
    fn new(stream: SendStream) -> Self {
        Self {
            stream,
            chunks: Vec::new(),
            finished: false,
            write: WriteState::default(),
        }
    }

    pub(crate) async fn write_frames(&mut self, frames: &[Bytes]) -> io::Result<()> {
        let mut start = 0;
        while start < frames.len() {
            let mut end = start;
            let mut total = 0usize;
            while end < frames.len() && total + frames[end].len() <= MAX_DATA_FRAME {
                total += frames[end].len();
                end += 1;
            }
            if end == start {
                total = frames[start].len();
                end = start + 1;
            }
            if total > 0 {
                self.write_data(&frames[start..end], total).await?;
            }
            start = end;
        }
        Ok(())
    }

    async fn write_data(&mut self, frames: &[Bytes], total: usize) -> io::Result<()> {
        let mut header = [0u8; 16];
        header[0] = h3::FRAME_DATA as u8;
        let n = 1 + h3::put_varint_slice(&mut header[1..], total as u64);
        self.stream
            .write_all(&header[..n])
            .await
            .map_err(io_error)?;

        self.chunks.clear();
        self.chunks.extend_from_slice(frames);
        self.stream
            .write_all_chunks(&mut self.chunks)
            .await
            .map_err(io_error)
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.finished = true;
        self.stream
            .finish()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "warp: CONNECT stream closed"))
    }
}

impl AsyncWrite for MasqueSend {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if this.write.remaining == 0 {
            let len = buf.len().min(MAX_DATA_FRAME);
            this.write.header[0] = h3::FRAME_DATA as u8;
            let header_len = 1 + h3::put_varint_slice(&mut this.write.header[1..], len as u64);
            this.write.header_len = header_len as u8;
            this.write.header_sent = 0;
            this.write.remaining = len;
        }

        while this.write.header_sent < this.write.header_len {
            let start = this.write.header_sent as usize;
            let end = this.write.header_len as usize;
            match AsyncWrite::poll_write(
                Pin::new(&mut this.stream),
                cx,
                &this.write.header[start..end],
            ) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => this.write.header_sent += n as u8,
            }
        }

        let want = buf.len().min(this.write.remaining);
        match AsyncWrite::poll_write(Pin::new(&mut this.stream), cx, &buf[..want]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(n)) => {
                this.write.remaining -= n;
                Poll::Ready(Ok(n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.finished {
            this.finished = true;
            let _ = this.stream.finish();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MasqueSend {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.stream.reset(VarInt::from_u32(0));
    }
}

pub(crate) struct MasqueRecv {
    stream: RecvStream,
    header: BytesMut,
    pending: BytesMut,
    remaining: u64,
    discard: bool,
    eof: bool,
}

impl MasqueRecv {
    fn new(stream: RecvStream, leftover: BytesMut) -> Self {
        Self {
            stream,
            header: leftover,
            pending: BytesMut::new(),
            remaining: 0,
            discard: false,
            eof: false,
        }
    }
}

fn poll_read_some(
    stream: &mut RecvStream,
    cx: &mut Context<'_>,
    dst: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut buf = ReadBuf::new(dst);
    match Pin::new(stream).poll_read(cx, &mut buf) {
        Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Pending => Poll::Pending,
    }
}

fn unexpected_eof() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "warp: CONNECT stream ended inside a DATA frame",
    )
}

impl AsyncRead for MasqueRecv {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }

            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }

            if this.remaining > 0 {
                if this.discard {
                    let mut scratch = [0u8; 512];
                    let want = (this.remaining as usize).min(scratch.len());
                    match poll_read_some(&mut this.stream, cx, &mut scratch[..want]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => return Poll::Ready(Err(unexpected_eof())),
                        Poll::Ready(Ok(n)) => {
                            this.remaining -= n as u64;
                            continue;
                        }
                    }
                }

                let want = (this.remaining as usize).min(buf.remaining());
                let filled = {
                    let unfilled = unsafe { buf.unfilled_mut() };
                    let mut sub = ReadBuf::uninit(&mut unfilled[..want]);
                    match Pin::new(&mut this.stream).poll_read(cx, &mut sub) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => sub.filled().len(),
                    }
                };
                if filled == 0 {
                    return Poll::Ready(Err(unexpected_eof()));
                }
                unsafe { buf.assume_init(filled) };
                buf.advance(filled);
                this.remaining -= filled as u64;
                return Poll::Ready(Ok(()));
            }

            match h3::get_frame_header(&this.header) {
                Some((ty, len, used)) => {
                    this.header.advance(used);
                    let take = (this.header.len() as u64).min(len) as usize;
                    if take > 0 {
                        this.pending = this.header.split_to(take);
                    }
                    this.remaining = len - take as u64;
                    this.discard = ty != h3::FRAME_DATA;
                    continue;
                }
                None => {
                    if this.eof {
                        return if this.header.is_empty() {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(unexpected_eof()))
                        };
                    }
                    let mut scratch = [0u8; 16];
                    match poll_read_some(&mut this.stream, cx, &mut scratch) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            this.eof = true;
                            if this.header.is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Ready(Err(unexpected_eof()));
                        }
                        Poll::Ready(Ok(n)) => this.header.extend_from_slice(&scratch[..n]),
                    }
                }
            }
        }
    }
}

fn io_error(e: quinn::WriteError) -> io::Error {
    match e {
        quinn::WriteError::Stopped(code) => io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("warp: CONNECT stream stopped by peer ({code})"),
        ),
        other => io::Error::other(other),
    }
}

pub(crate) fn build_tls_config(
    signing_key: &SigningKey,
    endpoint_spki: Option<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>> {
    let (cert_der, key_der) = self_signed_client_cert(signing_key)?;

    let provider = default_crypto_provider();
    let verifier: Arc<dyn ServerCertVerifier> = match endpoint_spki {
        Some(spki) => Arc::new(SpkiPinVerifier {
            expected: spki,
            algorithms: provider.signature_verification_algorithms,
        }),
        None => Arc::new(AcceptAnyCert {
            algorithms: provider.signature_verification_algorithms,
        }),
    };

    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("warp: rustls does not support TLS 1.3")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .context("warp: unusable device key for TLS client auth")?;
    config.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return Arc::clone(provider);
    }
    let _ = rustls::ClientConfig::builder();
    Arc::clone(
        rustls::crypto::CryptoProvider::get_default()
            .expect("rustls default crypto provider must be installed"),
    )
}

fn self_signed_client_cert(signing_key: &SigningKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_der = signing_key
        .to_pkcs8_der()
        .context("warp: encode device key")?;
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(key_der.as_bytes().to_vec()),
        &rcgen::PKCS_ECDSA_P256_SHA256,
    )
    .context("warp: rcgen rejected device key")?;

    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .context("warp: build certificate params")?;
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    let cert = params
        .self_signed(&key_pair)
        .context("warp: sign client certificate")?;

    Ok((cert.der().to_vec(), key_der.as_bytes().to_vec()))
}

fn extract_spki(cert: &[u8]) -> Option<&[u8]> {
    let (cert_body, _) = read_tlv(cert)?;
    let (tbs, _) = read_tlv(cert_body)?;
    let mut cursor = tbs;
    if cursor.first() == Some(&0xA0) {
        let (_, rest) = read_tlv(cursor)?;
        cursor = rest;
    }
    for _ in 0..5 {
        let (_, rest) = read_tlv(cursor)?;
        cursor = rest;
    }
    let (_, rest) = read_tlv(cursor)?;
    Some(&cursor[..cursor.len() - rest.len()])
}

fn read_tlv(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *buf.first()?;
    if first & 0x1F == 0x1F {
        return None;
    }
    let (len, len_bytes) = read_der_len(buf.get(1..)?)?;
    let header = 1 + len_bytes;
    let end = header.checked_add(len)?;
    Some((buf.get(header..end)?, buf.get(end..)?))
}

fn read_der_len(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || count > 4 {
        return None;
    }
    let mut len = 0usize;
    for &byte in buf.get(1..1 + count)? {
        len = (len << 8) | byte as usize;
    }
    Some((len, 1 + count))
}

#[derive(Debug)]
struct SpkiPinVerifier {
    expected: Vec<u8>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = extract_spki(end_entity.as_ref()).ok_or(rustls::Error::InvalidCertificate(
            rustls::CertificateError::BadEncoding,
        ))?;
        if spki == self.expected.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct AcceptAnyCert {
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use p256::pkcs8::EncodePublicKey;
    use tokio::io::AsyncReadExt;

    fn device_key() -> SigningKey {
        crate::warp::register::generate_device_key().unwrap().0
    }

    fn server_cert() -> (Vec<u8>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.der().to_vec(), key.serialize_der())
    }

    #[test]
    fn spki_extraction_matches_generated_certificate() {
        let key = device_key();
        let (cert, _) = self_signed_client_cert(&key).unwrap();
        let spki = key.verifying_key().to_public_key_der().unwrap();
        assert_eq!(extract_spki(&cert).unwrap(), spki.as_bytes());
    }

    #[test]
    fn spki_extraction_rejects_garbage() {
        assert!(extract_spki(b"not a certificate").is_none());
        assert!(extract_spki(&[]).is_none());
    }

    #[test]
    fn der_length_handles_long_form() {
        assert_eq!(read_der_len(&[0x05]), Some((5, 1)));
        assert_eq!(read_der_len(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(read_der_len(&[0x82, 0x01, 0x00]), Some((256, 3)));
        assert_eq!(read_der_len(&[0x85, 0, 0, 0, 0, 0]), None);
    }

    fn server_endpoint() -> (quinn::Endpoint, SocketAddr, Vec<u8>) {
        let (cert, key) = server_cert();
        let spki = extract_spki(&cert).unwrap().to_vec();

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )
            .unwrap();
        tls.alpn_protocols = vec![QUIC_ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        (endpoint, addr, spki)
    }

    async fn spawn_server(status: u16) -> (quinn::Endpoint, SocketAddr, Vec<u8>) {
        let (endpoint, addr, spki) = server_endpoint();

        let driver = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = driver.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        serve_connect(&mut send, &mut recv, status).await;
                    }
                    let _ = conn.closed().await;
                });
            }
        });

        (endpoint, addr, spki)
    }

    async fn serve_connect(send: &mut SendStream, recv: &mut RecvStream, status: u16) {
        let mut buf = BytesMut::new();
        let (ty, payload) = match read_frame(recv, &mut buf).await {
            Some(frame) => frame,
            None => return,
        };
        assert_eq!(ty, h3::FRAME_HEADERS);
        assert!(
            payload.windows(15).any(|w| w == b"example.com:443"),
            "authority missing from request headers"
        );

        let code = if (200..300).contains(&status) { 25 } else { 29 };
        let mut head = BytesMut::new();
        head.put_u8(0);
        head.put_u8(0);
        head.put_u8(0xC0 | code);
        if send
            .write_all(&frame_bytes(h3::FRAME_HEADERS, &head))
            .await
            .is_err()
        {
            return;
        }
        if !(200..300).contains(&status) {
            return;
        }

        loop {
            match read_frame(recv, &mut buf).await {
                Some((h3::FRAME_DATA, payload)) => {
                    let out = frame_bytes(h3::FRAME_DATA, &payload);
                    if send.write_all(&out).await.is_err() {
                        return;
                    }
                }
                Some(_) => continue,
                None => break,
            }
        }
        let _ = send.finish();
    }

    fn frame_bytes(ty: u64, payload: &[u8]) -> BytesMut {
        let mut out = BytesMut::with_capacity(payload.len() + 12);
        h3::put_varint(&mut out, ty);
        h3::put_varint(&mut out, payload.len() as u64);
        out.extend_from_slice(payload);
        out
    }

    async fn read_frame(recv: &mut RecvStream, buf: &mut BytesMut) -> Option<(u64, Vec<u8>)> {
        loop {
            if let Some((ty, len, used)) = h3::get_frame_header(buf) {
                let total = used + len as usize;
                if buf.len() >= total {
                    let payload = buf[used..total].to_vec();
                    buf.advance(total);
                    return Some((ty, payload));
                }
            }
            let chunk = recv.read_chunk(4096, true).await.ok()??;
            buf.extend_from_slice(&chunk.bytes);
        }
    }

    fn client_config(pin: Option<Vec<u8>>) -> (quinn::Endpoint, MasqueConfig) {
        let tls = build_tls_config(&device_key(), pin).unwrap();
        let cfg = MasqueConfig {
            sni: "localhost".to_string(),
            connect_timeout: Duration::from_secs(5),
            keepalive: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            tls,
        };
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(cfg.client_config().unwrap());
        (endpoint, cfg)
    }

    #[tokio::test]
    async fn connect_tunnel_roundtrips_payload() {
        let (server, addr, spki) = spawn_server(200).await;
        let (endpoint, cfg) = client_config(Some(spki));

        let conn = MasqueConn::establish(&endpoint, &cfg, addr).await.unwrap();
        assert!(conn.is_usable());
        let mut stream = conn.open("example.com:443").await.unwrap();

        let frames = vec![
            Bytes::from_static(b"hello warp"),
            Bytes::from(vec![0xABu8; 40_000]),
        ];
        stream.send.write_frames(&frames).await.unwrap();
        stream.send.shutdown().await.unwrap();

        let mut got = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.recv.read(&mut buf).await.unwrap() {
                0 => break,
                n => got.extend_from_slice(&buf[..n]),
            }
        }
        let expected: Vec<u8> = frames.iter().flat_map(|f| f.to_vec()).collect();
        assert_eq!(got, expected);

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }

    #[tokio::test]
    async fn open_streams_survive_the_connection_handle() {
        let (server, addr, spki) = spawn_server(200).await;
        let (endpoint, cfg) = client_config(Some(spki));

        let conn = MasqueConn::establish(&endpoint, &cfg, addr).await.unwrap();
        let mut stream = conn.open("example.com:443").await.unwrap();
        drop(conn);

        let frames = vec![Bytes::from_static(b"still here")];
        stream.send.write_frames(&frames).await.unwrap();
        stream.send.shutdown().await.unwrap();

        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            match stream.recv.read(&mut buf).await.unwrap() {
                0 => break,
                n => got.extend_from_slice(&buf[..n]),
            }
        }
        assert_eq!(got, b"still here");

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }

    #[tokio::test]
    async fn non_2xx_connect_is_rejected() {
        let (server, addr, spki) = spawn_server(403).await;
        let (endpoint, cfg) = client_config(Some(spki));

        let conn = MasqueConn::establish(&endpoint, &cfg, addr).await.unwrap();
        let err = match conn.open("example.com:443").await {
            Ok(_) => panic!("CONNECT must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("400"), "unexpected error: {err}");

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }

    #[tokio::test]
    async fn goaway_from_gateway_retires_the_connection() {
        let (endpoint, addr, spki) = server_endpoint();
        let driver = endpoint.clone();
        tokio::spawn(async move {
            if let Some(incoming) = driver.accept().await {
                let Ok(conn) = incoming.await else { return };
                if let Ok(mut uni) = conn.open_uni().await {
                    let mut control = BytesMut::new();
                    control.put_u8(h3::STREAM_CONTROL as u8);
                    control.put_u8(h3::FRAME_GOAWAY as u8);
                    control.put_u8(2);
                    control.put_u8(0);
                    control.put_u8(0);
                    let _ = uni.write_all(&control).await;
                }
                let _ = conn.closed().await;
            }
        });

        let (client, cfg) = client_config(Some(spki));
        let conn = MasqueConn::establish(&client, &cfg, addr).await.unwrap();
        assert!(conn.is_usable());

        for _ in 0..100 {
            if !conn.is_usable() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!conn.is_usable(), "GOAWAY should retire the connection");

        endpoint.close(VarInt::from_u32(0), b"done");
        client.close(VarInt::from_u32(0), b"done");
    }

    #[tokio::test]
    async fn wrong_pinned_key_fails_the_handshake() {
        let (server, addr, _spki) = spawn_server(200).await;
        let wrong = device_key().verifying_key().to_public_key_der().unwrap();
        let (endpoint, cfg) = client_config(Some(wrong.as_bytes().to_vec()));

        assert!(MasqueConn::establish(&endpoint, &cfg, addr).await.is_err());

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }

    #[test]
    fn control_stream_goaway_is_detected() {
        let mut buf = BytesMut::new();
        buf.put_u8(h3::FRAME_SETTINGS as u8);
        buf.put_u8(0);
        assert!(!control_has_goaway(&mut buf));
        assert!(buf.is_empty());

        buf.put_u8(h3::FRAME_GOAWAY as u8);
        buf.put_u8(1);
        buf.put_u8(0);
        assert!(control_has_goaway(&mut buf));
        assert!(buf.is_empty());
    }

    #[test]
    fn control_stream_partial_frame_waits_for_more_bytes() {
        let mut buf = BytesMut::new();
        buf.put_u8(h3::FRAME_GOAWAY as u8);
        buf.put_u8(4);
        buf.put_u8(0);
        assert!(!control_has_goaway(&mut buf));
        assert_eq!(buf.len(), 3);

        buf.put_u8(0);
        buf.put_u8(0);
        buf.put_u8(0);
        assert!(control_has_goaway(&mut buf));
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn insecure_mode_accepts_any_certificate() {
        let (server, addr, _spki) = spawn_server(200).await;
        let (endpoint, cfg) = client_config(None);

        let conn = MasqueConn::establish(&endpoint, &cfg, addr).await.unwrap();
        assert!(conn.open("example.com:443").await.is_ok());

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }
}

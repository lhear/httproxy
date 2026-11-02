//! 基于 quinn 的 MASQUE 客户端。
//!
//! 除了 RFC 9484 的 `CONNECT-IP`，Cloudflare 的 MASQUE 网关还提供**每条 TCP
//! 连接一个 HTTP/3 CONNECT 流**的 L4 转发模式，usque 的 `l4-socks` /
//! `l4-http-proxy` 走的就是这条路。对代理服务器来说它比 `CONNECT-IP` 更合适：
//! 不需要用户态 TCP/IP 协议栈，一条 QUIC bidi 流天然就是一条 TCP 连接，字节流
//! 可以直接落到 `AsyncRead`/`AsyncWrite` 上。
//!
//! 数据面刻意不引入 `h3` crate：CONNECT 只需要控制流、字段块和 DATA 帧这一小
//! 部分，自己编解码可以把载荷以 [`Bytes`] 的形式直接交给 quinn
//! （[`quinn::SendStream::write_all_chunks`]），避免多一次用户态拷贝，也避免
//! 为每条连接维护 QPACK 动态表。

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
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
use tracing::debug;

use super::h3;

/// 单条 DATA 帧的最大载荷。太大的帧会让对端缓冲更多数据，切成 64 KiB
/// 既不影响吞吐，也让帧头的相对开销可以忽略。
const MAX_DATA_FRAME: usize = 64 * 1024;

/// 解析响应头时读缓冲的上限。
const MAX_RESPONSE_HEAD_BUFFER: usize = 64 * 1024;

const QUIC_ALPN: &[u8] = b"h3";

pub(crate) struct MasqueConfig {
    pub endpoint: SocketAddr,
    pub sni: String,
    pub connect_timeout: Duration,
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    pub tls: Arc<rustls::ClientConfig>,
}

impl MasqueConfig {
    /// 组装 quinn 的客户端配置。
    ///
    /// 窗口参数按「每条连接可以同时跑几十上百条隧道」来定：单流 1 MiB、
    /// 整条连接 8 MiB，足够撑满带宽又不会让一条空闲连接占住几十 MB。
    pub(crate) fn client_config(&self) -> Result<quinn::ClientConfig> {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(self.keepalive));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(self.idle_timeout)
                .context("warp: invalid idle timeout")?,
        ));
        // 服务端不会向我们开流，给个很小的上限即可；上行流数量由对端决定，
        // `open_bi()` 会在超出配额时自动等待。
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

/// 一条已建立的 MASQUE 连接。
///
/// H3 的控制流与两条 QPACK 流必须一直保持打开：丢掉 `SendStream` 会发出
/// FIN / RESET_STREAM，对端会把它当成 H3 连接错误。
pub(crate) struct MasqueConn {
    conn: quinn::Connection,
    _control: SendStream,
    _qpack_encoder: SendStream,
    _qpack_decoder: SendStream,
}

impl MasqueConn {
    pub(crate) async fn establish(endpoint: &quinn::Endpoint, cfg: &MasqueConfig) -> Result<Self> {
        let connecting = endpoint
            .connect(cfg.endpoint, &cfg.sni)
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

        // 我们通告了动态表容量 0，这两个流永远不会承载数据，但 RFC 9204 要求
        // 端点必须创建它们，留着占位最省事。
        let mut qpack_encoder = conn.open_uni().await.context("warp: open QPACK encoder")?;
        qpack_encoder.write_all(&[h3::STREAM_QPACK_ENCODER as u8]).await?;
        let mut qpack_decoder = conn.open_uni().await.context("warp: open QPACK decoder")?;
        qpack_decoder.write_all(&[h3::STREAM_QPACK_DECODER as u8]).await?;

        debug!(endpoint = %cfg.endpoint, "warp: MASQUE connection established");

        Ok(Self {
            conn,
            _control: control,
            _qpack_encoder: qpack_encoder,
            _qpack_decoder: qpack_decoder,
        })
    }

    /// 连接是否还能用（对端关闭、超时或本地关闭都会让它不可用）。
    pub(crate) fn is_usable(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    pub(crate) fn close(&self) {
        self.conn.close(VarInt::from_u32(0), b"reconnect");
    }

    /// 在共享的 QUIC 连接上开一条 CONNECT 流。
    pub(crate) async fn open(&self, authority: &str) -> Result<MasqueStream> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("warp: open request stream")?;

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
            bail!("warp: CONNECT {authority} rejected with status {status}");
        }

        Ok(MasqueStream {
            send: MasqueSend::new(send),
            recv: MasqueRecv::new(recv, pending),
        })
    }
}

/// 一条 CONNECT 隧道：`send` 写请求体，`recv` 读响应体。
pub(crate) struct MasqueStream {
    pub(crate) send: MasqueSend,
    pub(crate) recv: MasqueRecv,
}

impl MasqueStream {
    /// 把整条流当成一个双工字节流用。
    ///
    /// 隧道数据面走的是 `write_frames` / `MasqueRecv`（零拷贝、批量），
    /// 但 DoT 这类需要 `AsyncRead + AsyncWrite` 的调用方只能在整条流上工作。
    pub(crate) fn into_io(self) -> DuplexIo {
        DuplexIo(Box::pin(tokio::io::join(self.recv, self.send)))
    }
}

trait Duplex: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> Duplex for T {}

/// 一条 CONNECT 流的双工视图。
pub(crate) struct DuplexIo(Pin<Box<dyn Duplex + Send>>);

impl AsyncRead for DuplexIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self.get_mut().0.as_mut(), cx, buf)
    }
}

impl AsyncWrite for DuplexIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self.get_mut().0.as_mut(), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self.get_mut().0.as_mut(), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self.get_mut().0.as_mut(), cx)
    }
}

/// 等待响应头，返回状态码和紧随其后的字节（可能已经是 DATA 载荷）。
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
            // 其它帧（理论上不会出现）整帧丢掉
            buf.advance(total);
        }

        if buf.len() > MAX_RESPONSE_HEAD_BUFFER {
            bail!("warp: CONNECT response for {authority} exceeded {MAX_RESPONSE_HEAD_BUFFER} bytes");
        }

        match recv.read_chunk(4096, true).await.context("warp: read response")? {
            Some(chunk) => buf.extend_from_slice(&chunk.bytes),
            None => bail!("warp: connection closed before CONNECT response for {authority}"),
        }
    }
}

/// 写侧：把上行的连续帧包成 H3 DATA 帧。
pub(crate) struct MasqueSend {
    stream: SendStream,
    /// 复用的一次性 chunk 列表，避免每批数据都重新分配
    chunks: Vec<Bytes>,
    finished: bool,
    /// `AsyncWrite` 路径的帧头 / 帧内偏移（隧道数据面走 `write_frames`，不碰它）
    write: WriteState,
}

#[derive(Default)]
struct WriteState {
    header: [u8; 16],
    header_len: u8,
    header_sent: u8,
    /// 当前 DATA 帧还差多少载荷字节
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

    /// 把一段连续帧写出去。
    ///
    /// 载荷以 [`Bytes`] 直接交给 quinn，不经过任何中间缓冲：`write_all_chunks`
    /// 把 chunk 挂到流上而不是拷进发送缓冲。
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
                // 单帧就超过上限：仍然要为它开一个 DATA 帧
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

    /// 半关闭：发出 FIN，告诉对端请求体结束。
    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        self.finished = true;
        self.stream.finish().map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "warp: CONNECT stream closed")
        })
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

        // 帧头必须整段发出去，之后才能碰调用方的缓冲区
        while this.write.header_sent < this.write.header_len {
            let start = this.write.header_sent as usize;
            let end = this.write.header_len as usize;
            match AsyncWrite::poll_write(Pin::new(&mut this.stream), cx, &this.write.header[start..end]) {
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
        // quinn 自己管理发送缓冲，没有需要显式 flush 的东西
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
            // quinn 自己会在 drop 时补一次 finish，这里不需要做什么
            return;
        }
        // 没有半关闭就被丢弃 = 隧道被中断：重置流，让网关立刻断掉目标连接，
        // 而不是等对端把响应发完
        let _ = self.stream.reset(VarInt::from_u32(0));
    }
}

/// 读侧：把 H3 DATA 帧的载荷还原成字节流。
pub(crate) struct MasqueRecv {
    stream: RecvStream,
    /// 帧头（以及一次多读出来的少量字节）
    header: BytesMut,
    /// 已经收下来但还没交给调用方的载荷
    pending: BytesMut,
    /// 当前帧还差多少字节
    remaining: u64,
    /// 当前帧不是 DATA：读出来直接丢弃
    discard: bool,
    eof: bool,
}

impl MasqueRecv {
    /// `leftover` 是响应头之后已经读进缓冲的字节，可能已经是 DATA 载荷。
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

/// 从 quinn 读一小块到切片，返回读到的字节数（0 表示 FIN）。
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

            // 先把上一次多读出来的载荷交出去
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
                    // SAFETY: 只把 `want` 字节的未初始化区交给 quinn 填，
                    // 填多少由 `ReadBuf::filled()` 报告，随后 assume_init 的
                    // 正是这段已被写入的字节。
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

            // 当前帧读完了：解析下一个帧头
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

// ---------------------------------------------------------------------------
// TLS：自签客户端证书 + 端点公钥钉扎
// ---------------------------------------------------------------------------

/// 构造 QUIC 用的 rustls 客户端配置。
///
/// Cloudflare 的 MASQUE 端点证书不是公有 CA 签的（官方客户端也是靠钉扎
/// `config.peers[0].public_key` 来认端点），所以这里不用根证书，而是把握手
/// 拿到的叶子证书 SPKI 与注册时登记的端点公钥逐字节比较。
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
    Ok(Arc::new(config))
}

fn default_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    if let Some(provider) = rustls::crypto::CryptoProvider::get_default() {
        return Arc::clone(provider);
    }
    // 触发 rustls 按编译期特性安装默认 provider，再取回来
    let _ = rustls::ClientConfig::builder();
    Arc::clone(
        rustls::crypto::CryptoProvider::get_default()
            .expect("rustls default crypto provider must be installed"),
    )
}

/// 用设备私钥签一张自签证书 —— 就是 Cloudflare 用来识别设备的客户端证书。
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
    // 有效期只是形式：端点靠钉扎与设备登记识别，不看签发时间
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    let cert = params
        .self_signed(&key_pair)
        .context("warp: sign client certificate")?;

    Ok((cert.der().to_vec(), key_der.as_bytes().to_vec()))
}

/// 从 X.509 证书里取出 `SubjectPublicKeyInfo` 的完整 DER（含外层 SEQUENCE）。
fn extract_spki(cert: &[u8]) -> Option<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (cert_body, _) = read_tlv(cert)?;
    // TBSCertificate ::= SEQUENCE { [0] version, serialNumber, signature,
    //                               issuer, validity, subject, subjectPublicKeyInfo, ... }
    let (tbs, _) = read_tlv(cert_body)?;
    let mut cursor = tbs;
    if cursor.first() == Some(&0xA0) {
        let (_, rest) = read_tlv(cursor)?;
        cursor = rest;
    }
    // serialNumber / signature / issuer / validity / subject
    for _ in 0..5 {
        let (_, rest) = read_tlv(cursor)?;
        cursor = rest;
    }
    let (_, rest) = read_tlv(cursor)?;
    Some(&cursor[..cursor.len() - rest.len()])
}

/// 读一个 DER TLV，返回（内容，剩余字节）。
fn read_tlv(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    // tag
    let first = *buf.first()?;
    if first & 0x1F == 0x1F {
        // 高 tag number 形式：我们只处理单字节 tag
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
        // 不定长或超长长度都不该出现在证书里
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

/// `insecure_skip_verify = true` 时使用：只保留 TLS 1.3 的签名校验。
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

    // -----------------------------------------------------------------
    // 回环 QUIC 上的端到端测试：一个最小的 H3 CONNECT 服务端
    // -----------------------------------------------------------------

    async fn spawn_server(status: u16) -> (quinn::Endpoint, SocketAddr, Vec<u8>) {
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

        let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .unwrap();
        let addr = endpoint.local_addr().unwrap();

        let driver = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = driver.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        serve_connect(&mut send, &mut recv, status).await;
                    }
                    // 必须保持连接，直到客户端自己关掉：提前 drop 掉 Connection
                    // 会让 quinn 立刻用 code 0 关闭连接，刚写出去的数据就丢了。
                    let _ = conn.closed().await;
                });
            }
        });

        (endpoint, addr, spki)
    }

    async fn serve_connect(send: &mut SendStream, recv: &mut RecvStream, status: u16) {
        // 请求头：只要看到 CONNECT 的 authority 就算通过
        let mut buf = BytesMut::new();
        let (ty, payload) = match read_frame(recv, &mut buf).await {
            Some(frame) => frame,
            None => return,
        };
        assert_eq!(ty, h3::FRAME_HEADERS);
        // `:method: CONNECT` 用的是静态表索引，块里能看到的是字面量 authority
        assert!(
            payload.windows(15).any(|w| w == b"example.com:443"),
            "authority missing from request headers"
        );

        let code = if (200..300).contains(&status) { 25 } else { 29 };
        let mut head = BytesMut::new();
        head.put_u8(0);
        head.put_u8(0);
        head.put_u8(0xC0 | code); // :status 200 / 400
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

        // 把 DATA 载荷原样回显
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

    /// 读一个完整的帧，返回（类型，载荷）；对端 FIN 时返回 `None`。
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

    fn client_config(addr: SocketAddr, pin: Option<Vec<u8>>) -> (quinn::Endpoint, MasqueConfig) {
        let tls = build_tls_config(&device_key(), pin).unwrap();
        let cfg = MasqueConfig {
            endpoint: addr,
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
        let (endpoint, cfg) = client_config(addr, Some(spki));

        let conn = MasqueConn::establish(&endpoint, &cfg).await.unwrap();
        assert!(conn.is_usable());
        let mut stream = conn.open("example.com:443").await.unwrap();

        let frames = vec![
            Bytes::from_static(b"hello warp"),
            Bytes::from(vec![0xABu8; 40_000]),
        ];
        stream.send.write_frames(&frames).await.unwrap();
        stream.send.shutdown().await.unwrap();

        // 服务端把 DATA 载荷原样回显
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
    async fn non_2xx_connect_is_rejected() {
        let (server, addr, spki) = spawn_server(403).await;
        let (endpoint, cfg) = client_config(addr, Some(spki));

        let conn = MasqueConn::establish(&endpoint, &cfg).await.unwrap();
        let err = match conn.open("example.com:443").await {
            Ok(_) => panic!("CONNECT must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("400"), "unexpected error: {err}");

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }

    #[tokio::test]
    async fn wrong_pinned_key_fails_the_handshake() {
        let (server, addr, _spki) = spawn_server(200).await;
        // 换一个不相干的 SPKI 作为钉扎目标
        let wrong = device_key().verifying_key().to_public_key_der().unwrap();
        let (endpoint, cfg) = client_config(addr, Some(wrong.as_bytes().to_vec()));

        assert!(MasqueConn::establish(&endpoint, &cfg).await.is_err());

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }

    #[tokio::test]
    async fn insecure_mode_accepts_any_certificate() {
        let (server, addr, _spki) = spawn_server(200).await;
        let (endpoint, cfg) = client_config(addr, None);

        let conn = MasqueConn::establish(&endpoint, &cfg).await.unwrap();
        assert!(conn.open("example.com:443").await.is_ok());

        server.close(VarInt::from_u32(0), b"done");
        endpoint.close(VarInt::from_u32(0), b"done");
    }
}

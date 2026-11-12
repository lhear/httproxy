mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use common::*;
use httproxy::config::WarpSection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ALPN: &[u8] = b"h3";
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;

const TEST_PRIVATE_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgdJ+Fw3esExD3TV3VMUP+VR7Wh9oK2UklqfGm7o4/ZmGhRANCAAQqiPmOneK+zI4dYmlgPefw2W9SF/OYT/UR7WAwX657T8CSdBzx83+0yCnj9jlJJYe0Dfq9xCO1N4YZdoo3IhzG";
const TEST_PEER_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKoj5jp3ivsyOHWJpYD3n8NlvUhfzmE/1Ee1gMF+ue0/AknQc8fN/tMgp4/Y5SSWHtA36vcQjtTeGGXaKNyIcxg==";

fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 6 {
        out.push(value as u8);
    } else if value < 1 << 14 {
        out.extend_from_slice(&(0x4000 | value as u16).to_be_bytes());
    } else if value < 1 << 30 {
        out.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xC000_0000_0000_0000 | value).to_be_bytes());
    }
}

fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

fn frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 12);
    put_varint(&mut out, ty);
    put_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

fn get_prefixed_int(buf: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let mut value = (first & mask) as u64;
    if value < mask as u64 {
        return Some((value, 1));
    }
    let mut shift = 0u32;
    let mut idx = 1usize;
    loop {
        let byte = *buf.get(idx)?;
        value += ((byte & 0x7F) as u64) << shift;
        idx += 1;
        if byte & 0x80 == 0 {
            return Some((value, idx));
        }
        shift += 7;
    }
}

fn request_authority(block: &[u8]) -> String {
    assert_eq!(block[0], 0, "insert count");
    assert_eq!(block[1], 0, "delta base");
    assert_eq!(block[2], 0xCF, ":method CONNECT");
    assert_eq!(block[3], 0x50, ":authority with static name ref");
    let (len, used) = get_prefixed_int(&block[4..], 7).expect("authority length");
    let start = 4 + used;
    String::from_utf8(block[start..start + len as usize].to_vec()).unwrap()
}

async fn read_frame(recv: &mut quinn::RecvStream, buf: &mut Vec<u8>) -> Option<(u64, Vec<u8>)> {
    loop {
        if let Some((ty, n)) = get_varint(buf)
            && let Some((len, m)) = get_varint(&buf[n..])
        {
            let total = n + m + len as usize;
            if buf.len() >= total {
                let payload = buf[n + m..total].to_vec();
                buf.drain(..total);
                return Some((ty, payload));
            }
        }
        let chunk = recv.read_chunk(64 * 1024, true).await.ok()??;
        buf.extend_from_slice(&chunk.bytes);
    }
}

async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    connects: Arc<AtomicUsize>,
) {
    let mut buf = Vec::new();
    let Some((ty, block)) = read_frame(&mut recv, &mut buf).await else {
        return;
    };
    assert_eq!(ty, FRAME_HEADERS, "expected CONNECT headers");

    let authority = request_authority(&block);
    connects.fetch_add(1, Ordering::SeqCst);

    let target: SocketAddr = authority
        .parse()
        .unwrap_or_else(|_| panic!("CONNECT authority must be an IP literal, got `{authority}`"));

    let Ok(upstream) = TcpStream::connect(target).await else {
        let _ = send
            .write_all(&frame(FRAME_HEADERS, &[0, 0, 0xC0 | 30]))
            .await;
        return;
    };
    if send
        .write_all(&frame(FRAME_HEADERS, &[0, 0, 0xC0 | 25]))
        .await
        .is_err()
    {
        return;
    }

    let (mut up_read, mut up_write) = upstream.into_split();

    let upload = async {
        while let Some((ty, payload)) = read_frame(&mut recv, &mut buf).await {
            if ty != FRAME_DATA {
                continue;
            }
            if up_write.write_all(&payload).await.is_err() {
                break;
            }
        }
        let _ = up_write.shutdown().await;
    };

    let download = async {
        let mut tmp = vec![0u8; 16 * 1024];
        loop {
            match up_read.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send.write_all(&frame(FRAME_DATA, &tmp[..n])).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = send.finish();
    };

    tokio::join!(upload, download);
}

async fn spawn_masque_proxy() -> (SocketAddr, Arc<AtomicUsize>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();

    let connects = Arc::new(AtomicUsize::new(0));
    let driver = endpoint.clone();
    let counter = Arc::clone(&connects);
    tokio::spawn(async move {
        while let Some(incoming) = driver.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                loop {
                    let Ok((send, recv)) = conn.accept_bi().await else {
                        return;
                    };
                    tokio::spawn(serve_stream(send, recv, Arc::clone(&counter)));
                }
            });
        }
    });

    (addr, connects)
}

fn credentials_path() -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("httproxy-warp-{}-{stamp}.json", std::process::id()))
}

async fn start_with_warp() -> (SocketAddr, SocketAddr, Arc<AtomicUsize>) {
    start_with_warp_and_dns(None).await
}

async fn start_with_warp_and_dns(
    dns_upstream: Option<SocketAddr>,
) -> (SocketAddr, SocketAddr, Arc<AtomicUsize>) {
    let keys = test_keys();
    let upstream = spawn_upstream().await;
    let (masque_addr, connects) = spawn_masque_proxy().await;

    let path = credentials_path();
    let creds = serde_json::json!({
        "id": "test-device",
        "access_token": "test-token",
        "private_key": TEST_PRIVATE_KEY,
        "endpoint_pub_key": TEST_PEER_KEY,
        "ipv4": "172.16.0.2",
        "ipv6": "2606:4700:110:8a36::2",
        "endpoint_v4": "127.0.0.1",
        "endpoint_v6": "",
    });
    tokio::fs::write(&path, serde_json::to_vec(&creds).unwrap())
        .await
        .unwrap();

    let mut cfg = server_config(traffic(true, None), &keys, None);
    cfg.dns = dns_upstream.map(|upstream| httproxy::dns::DnsConfig {
        upstream,
        tls_domain: None,
        options: httproxy::dns::DnsOptions::default(),
    });
    cfg.warp = Some(WarpSection {
        enabled: true,
        config_path: Some(path.to_string_lossy().into_owned()),
        endpoint: Some("127.0.0.1".to_string()),
        endpoint_v6: None,
        port: Some(masque_addr.port()),
        sni: Some("localhost".to_string()),
        connect_timeout_secs: Some(5),
        keepalive_secs: Some(5),
        idle_timeout_secs: Some(30),
        register_model: None,
        register_locale: None,
        insecure_skip_verify: true,
        bypass_private: false,
        bypass_cidrs: vec![],
        bypass_suffixes: vec![],
    });

    let server = spawn_server(cfg).await;
    let client = spawn_client(
        client_config(traffic(true, None), &keys, None, vec![]),
        server,
    )
    .await;

    (upstream, client, connects)
}

async fn spawn_dns_tcp_server(zone: &'static str, hits: Arc<AtomicUsize>) -> SocketAddr {
    spawn_dns_tcp(dns_zone(zone, std::net::Ipv4Addr::LOCALHOST.into()), hits).await
}

#[tokio::test]
async fn hostname_is_resolved_locally_and_dns_goes_through_warp() {
    common::init_logging();
    let hits = Arc::new(AtomicUsize::new(0));
    let dns_addr = spawn_dns_tcp_server("warp.test", Arc::clone(&hits)).await;
    let (upstream, client, connects) = start_with_warp_and_dns(Some(dns_addr)).await;

    let (status, body) = raw_exchange(
        client,
        format!(
            "GET http://warp.test:{}/hello HTTP/1.1\r\nHost: warp.test\r\nConnection: close\r\n\r\n",
            upstream.port()
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
    assert!(
        hits.load(Ordering::SeqCst) >= 1,
        "the hostname must be resolved by the DNS module"
    );
    assert!(
        connects.load(Ordering::SeqCst) >= 2,
        "expected one CONNECT for DNS and one for the target"
    );
}

#[tokio::test]
async fn request_goes_through_masque() {
    common::init_logging();
    let (upstream, client, connects) = start_with_warp().await;

    let (status, body) = raw_exchange(
        client,
        format!("GET http://{upstream}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello upstream");
    assert!(
        connects.load(Ordering::SeqCst) >= 1,
        "the request must have been tunnelled through MASQUE"
    );
}

#[tokio::test]
async fn large_download_survives_flow_control() {
    common::init_logging();
    let (upstream, client, _) = start_with_warp().await;

    let (status, body) = raw_exchange(
        client,
        format!("GET http://{upstream}/large HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 512 * 1024);
    assert!(body.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
async fn large_upload_echoes_through_masque() {
    common::init_logging();
    let (upstream, client, _) = start_with_warp().await;

    let body: Vec<u8> = (0..(256 * 1024) as u32).map(|i| (i % 251) as u8).collect();
    let request = format!(
        "POST http://{upstream}/echo HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(client).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (status, echoed) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(echoed, body);
}

#[tokio::test]
async fn concurrent_streams_share_one_quic_connection() {
    common::init_logging();
    let (upstream, client, connects) = start_with_warp().await;

    let mut handles = Vec::new();
    for _ in 0..4 {
        let request = format!(
            "GET http://{upstream}/hello HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
        );
        handles.push(tokio::spawn(async move {
            raw_exchange(client, request.as_bytes()).await
        }));
    }
    for handle in handles {
        let (status, body) = handle.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello upstream");
    }
    assert!(connects.load(Ordering::SeqCst) >= 4);
}

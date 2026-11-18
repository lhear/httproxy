mod common;

use common::*;
use httproxy_core::config::ClientProxyAuth;
use httproxy_core::dns::{DnsConfig, DnsOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

async fn authenticated_socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    stream
        .write_all(&[1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'])
        .await
        .unwrap();
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(
        &target
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header, [5, 0, 0, 1]);
    let mut address_and_port = [0; 6];
    stream.read_exact(&mut address_and_port).await.unwrap();
    stream
}

fn dns_query(id: u16, domain: &str) -> Vec<u8> {
    let mut query = Vec::with_capacity(domain.len() + 18);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

#[tokio::test]
async fn authenticated_socks_supports_tcp_and_only_udp_dns() {
    let keys = test_keys();
    common::init_logging();
    let upstream = spawn_upstream().await;
    let query_count = Arc::new(AtomicUsize::new(0));
    let dns_addr = spawn_dns_udp(
        dns_zone("socks.test", IpAddr::V4(Ipv4Addr::new(9, 8, 7, 6))),
        Arc::clone(&query_count),
    )
    .await;
    let dns_target = SocketAddr::from(([127, 0, 0, 1], 53));
    let mut server_cfg = server_config(traffic(true, None), &keys, None);
    server_cfg.dns = Some(DnsConfig {
        upstream: dns_addr,
        tls_domain: None,
        options: DnsOptions::default(),
    });
    let server = spawn_server(server_cfg).await;
    let mut client_cfg = client_config(traffic(true, None), &keys, None, vec![]);
    client_cfg.client.proxy_auth = Some(ClientProxyAuth {
        username: "user".to_owned(),
        password: "pass".to_owned(),
    });
    let client = spawn_client(client_cfg, server).await;

    let mut tcp = authenticated_socks_connect(client, upstream).await;
    tcp.write_all(b"GET /hello HTTP/1.1\r\nHost: upstream\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"hello upstream"));

    let mut association = TcpStream::connect(client).await.unwrap();
    association.write_all(&[5, 1, 2]).await.unwrap();
    let mut auth_response = [0; 2];
    association.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [5, 2]);
    association
        .write_all(&[1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'])
        .await
        .unwrap();
    association.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [1, 0]);
    association
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut relay_header = [0; 4];
    association.read_exact(&mut relay_header).await.unwrap();
    assert_eq!(relay_header, [5, 0, 0, 1]);
    let mut relay_addr = [0; 6];
    association.read_exact(&mut relay_addr).await.unwrap();
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
            relay_addr[0],
            relay_addr[1],
            relay_addr[2],
            relay_addr[3],
        )),
        u16::from_be_bytes([relay_addr[4], relay_addr[5]]),
    );
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let blocked = httproxy_client::socks5::encode_udp_packet(
        &httproxy_client::socks5::Target::Ip(SocketAddr::new(dns_target.ip(), 80)),
        b"not dns",
    );
    udp.send_to(&blocked, relay).await.unwrap();
    let mut packet = [0; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(150), udp.recv_from(&mut packet))
            .await
            .is_err()
    );

    let query = dns_query(0x4567, "socks.test");
    let request = httproxy_client::socks5::encode_udp_packet(
        &httproxy_client::socks5::Target::Ip(dns_target),
        &query,
    );
    udp.send_to(&request, relay).await.unwrap();
    let (length, _) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    let (source, dns_response) =
        httproxy_client::socks5::parse_udp_packet(&packet[..length]).unwrap();
    assert_eq!(source, httproxy_client::socks5::Target::Ip(dns_target));
    assert_eq!(&dns_response[..2], &0x4567u16.to_be_bytes());
    assert!(query_count.load(Ordering::Relaxed) >= 1);

    let resolved = query_count.load(Ordering::Relaxed);
    let mut repeat = query.clone();
    repeat[..2].copy_from_slice(&0x9999u16.to_be_bytes());
    let request = httproxy_client::socks5::encode_udp_packet(
        &httproxy_client::socks5::Target::Ip(dns_target),
        &repeat,
    );
    udp.send_to(&request, relay).await.unwrap();
    let (length, _) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();
    let (_, dns_response) = httproxy_client::socks5::parse_udp_packet(&packet[..length]).unwrap();
    assert_eq!(&dns_response[..2], &0x9999u16.to_be_bytes());
    assert_eq!(
        query_count.load(Ordering::Relaxed),
        resolved,
        "a repeated query must be answered from the client cache"
    );

    let mut dns_tcp = authenticated_socks_connect(client, dns_target).await;
    dns_tcp
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    dns_tcp.write_all(&query).await.unwrap();
    let mut length = [0; 2];
    dns_tcp.read_exact(&mut length).await.unwrap();
    let mut tcp_response = vec![0; u16::from_be_bytes(length) as usize];
    dns_tcp.read_exact(&mut tcp_response).await.unwrap();
    assert_eq!(&tcp_response[..2], &0x4567u16.to_be_bytes());
    assert!(query_count.load(Ordering::Relaxed) >= 2);
}

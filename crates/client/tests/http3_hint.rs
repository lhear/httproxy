use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use httproxy_client::cronet::Client;
use tokio::net::{TcpListener, UdpSocket};

fn is_quic_initial(packet: &[u8]) -> bool {
    packet.len() >= 5 && packet[0] & 0x80 != 0 && packet[1..5] == [0, 0, 0, 1]
}

async fn count_quic(hint: Option<&str>, window: Duration) -> usize {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.local_addr().unwrap().port();
    let tcp = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

    let packets = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&packets);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, _)) = udp.recv_from(&mut buf).await {
            if is_quic_initial(&buf[..len]) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = tcp.accept().await {
            held.push(stream);
        }
    });

    let client = Client::with_http3_options(None, None, false, hint.map(|host| (host, port)))
        .expect("cronet engine");
    let url = format!("https://127.0.0.1:{port}/probe");
    let request = tokio::spawn(async move {
        let _ = client
            .post(&url)
            .body(bytes::Bytes::from_static(b"probe"))
            .send()
            .await;
    });

    let deadline = tokio::time::Instant::now() + window;
    while packets.load(Ordering::Relaxed) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    request.abort();
    packets.load(Ordering::Relaxed)
}

#[tokio::test]
async fn hint_sends_quic_packets_to_the_hinted_port() {
    let packets = count_quic(Some("127.0.0.1"), Duration::from_secs(15)).await;
    assert!(packets > 0, "the hint must trigger QUIC, saw {packets}");
}

#[tokio::test]
async fn no_hint_keeps_quic_quiet() {
    let packets = count_quic(None, Duration::from_secs(3)).await;
    assert_eq!(packets, 0, "QUIC started without a hint");
}

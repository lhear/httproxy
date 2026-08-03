mod common;

use common::*;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;

async fn start_rotating(binary: bool, max_download_bytes: u64) -> (SocketAddr, SocketAddr) {
    let upstream = spawn_upstream().await;
    let server = spawn_server(server_config(
        traffic(binary, Some(max_download_bytes)),
        None,
        None,
    ))
    .await;
    let client = spawn_client(
        client_config(
            traffic(binary, Some(max_download_bytes)),
            None,
            None,
            vec![],
        ),
        server,
    )
    .await;
    (upstream, client)
}

#[tokio::test]
async fn rotating_download_reassembles_binary() {
    common::init_logging();
    let (upstream, client) = start_rotating(true, 64 * 1024).await;
    let url = format!("http://{upstream}/large");
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 512 * 1024);
    assert!(body.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
async fn rotating_download_reassembles_json() {
    common::init_logging();
    let (upstream, client) = start_rotating(false, 64 * 1024).await;
    let url = format!("http://{upstream}/large");
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 512 * 1024);
    assert!(body.iter().all(|&b| b == 0xAB));
}

#[tokio::test]
async fn rotating_with_upload_echo() {
    common::init_logging();
    let (upstream, client) = start_rotating(true, 256 * 1024).await;
    let body: Vec<u8> = (0..(512 * 1024) as u32).map(|i| (i % 251) as u8).collect();
    let url = format!("http://{upstream}/echo");
    let request = format!(
        "POST {url} HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(client).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let (status, echoed) = read_response(&mut stream).await;
    assert_eq!(status, 200);
    assert_eq!(echoed, body);
}

#[tokio::test]
async fn prefetch_continuation_path_works_end_to_end() {
    common::init_logging();
    let (upstream, client) = start_rotating(true, 24 * 1024 * 1024).await;
    let url = format!("http://{upstream}/big");
    let (status, body) = raw_exchange(
        client,
        format!("GET {url} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body.len(), 32 * 1024 * 1024);
    assert!(body.iter().all(|&b| b == 0xCD));
}

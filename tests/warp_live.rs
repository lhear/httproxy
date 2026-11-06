mod common;

use common::*;
use httproxy::config::WarpSection;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

fn live_credentials_path() -> String {
    std::env::temp_dir()
        .join("httproxy-warp-live.json")
        .to_string_lossy()
        .into_owned()
}

#[tokio::test]
#[ignore = "requires real network access to Cloudflare WARP"]
async fn real_warp_serves_a_page() {
    common::init_logging();

    let mut cfg = server_config(traffic(true, None), None, None);
    cfg.dns = Some(httproxy::dns::DnsConfig {
        upstream: "1.1.1.1:53".parse().unwrap(),
        tls_domain: None,
        options: httproxy::dns::DnsOptions::default(),
    });
    cfg.warp = Some(WarpSection {
        enabled: true,
        config_path: Some(live_credentials_path()),
        endpoint: None,
        endpoint_v6: None,
        port: None,
        sni: None,
        connect_timeout_secs: Some(15),
        keepalive_secs: Some(25),
        idle_timeout_secs: Some(60),
        register_model: None,
        register_locale: None,
        insecure_skip_verify: false,
        bypass_private: true,
        bypass_cidrs: vec![],
        bypass_suffixes: vec![],
    });

    let server = spawn_server(cfg).await;
    let client = spawn_client(
        client_config(traffic(true, None), None, None, vec![]),
        server,
    )
    .await;

    let exchange = async {
        let mut stream = TcpStream::connect(client).await.unwrap();
        stream
            .write_all(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let (status, body) = read_response(&mut stream).await;
        (status, body)
    };

    let (status, body) = tokio::time::timeout(Duration::from_secs(60), exchange)
        .await
        .expect("live WARP request timed out");

    assert_eq!(status, 200, "unexpected status from example.com");
    assert!(
        String::from_utf8_lossy(&body).contains("Example Domain"),
        "unexpected body: {}",
        String::from_utf8_lossy(&body[..body.len().min(300)])
    );
}

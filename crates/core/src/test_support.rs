use crate::crypto::AesFrameCipher;
use crate::shaper::{EncodingType, FrameCipher, PaddingConfig, TrafficConfig};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

pub const TEST_KEY_SEED: u8 = 7;

pub fn plain_traffic(encoding: EncodingType) -> TrafficConfig {
    TrafficConfig {
        global: PaddingConfig {
            padding_threshold: 0,
            padding_range: [0, 0],
        },
        handshake: None,
        stages: vec![],
        encoding_type: encoding,
        max_download_bytes: None,
    }
}

pub fn test_cipher() -> AesFrameCipher {
    cipher_with_key(TEST_KEY_SEED)
}

pub fn cipher_with_key(seed: u8) -> AesFrameCipher {
    AesFrameCipher::new(&Zeroizing::new([seed; 32]))
}

pub fn test_cipher_arc() -> Arc<AesFrameCipher> {
    Arc::new(test_cipher())
}

pub fn test_cipher_dyn() -> Arc<dyn FrameCipher> {
    test_cipher_arc()
}

pub fn stream_cipher_arc(seed: u8) -> Arc<dyn FrameCipher> {
    Arc::new(crate::crypto::StreamCipher::new(&Zeroizing::new(
        [seed; 32],
    )))
}

pub async fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let client = TcpStream::connect(addr).await.unwrap();
    (accept.await.unwrap(), client)
}

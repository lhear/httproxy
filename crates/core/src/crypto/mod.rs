mod cipher;
mod handshake;
mod keys;
mod tls;

pub use cipher::PlainFrameCipher;
pub use cipher::{AesFrameCipher, NONCE_LEN, StreamCipher, TAG_LEN, decrypt_bytes, encrypt_bytes};
pub use handshake::expand_key;
pub use handshake::{
    derive_connection_keys, derive_cookie_stream_key, derive_handshake_key, derive_initial_master,
};
pub use keys::{
    KEY_LEN, b64_to_private_key, b64_to_public_key, diffie_hellman, generate_keypair,
    private_key_to_b64, public_key_from_slice, public_key_to_b64,
};
pub use tls::TlsInspector;
pub use x25519_dalek::{PublicKey, StaticSecret};

pub type ConnectionKeys = (
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
);

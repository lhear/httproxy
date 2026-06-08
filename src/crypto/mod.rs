mod cipher;
mod handshake;
mod keys;

pub use cipher::{AesFrameCipher, decrypt_bytes, encrypt_bytes};
pub use handshake::{
    derive_connection_keys, derive_cookie_stream_key, derive_handshake_key, derive_initial_master,
};
pub use keys::{
    b64_to_private_key, b64_to_public_key, bytes_to_encapsulation_key, diffie_hellman,
    generate_keypair, generate_mlkem_keypair, mlkem_decapsulate, mlkem_encapsulate,
    private_key_to_b64, public_key_to_b64,
};

pub type AesKey = aes_gcm::Key<aes_gcm::Aes256Gcm>;

pub type ConnectionKeys = (
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
);

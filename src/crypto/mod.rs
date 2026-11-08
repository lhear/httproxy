mod cipher;
mod handshake;
mod keys;

pub use aws_lc_rs::kem::{DecapsulationKey, EncapsulationKey};
pub(crate) use cipher::PlainFrameCipher;
pub use cipher::{AesFrameCipher, NONCE_LEN, TAG_LEN, decrypt_bytes, encrypt_bytes};
pub(crate) use handshake::expand_key;
pub use handshake::{
    derive_connection_keys, derive_cookie_stream_key, derive_handshake_key, derive_initial_master,
};
pub use keys::{
    b64_to_mlkem_private_key, b64_to_mlkem_public_key, bytes_to_encapsulation_key, diffie_hellman,
    generate_keypair, generate_mlkem_keypair, mlkem_decapsulate, mlkem_encapsulate,
    mlkem_private_key_to_b64, mlkem_public_key_bytes, mlkem_public_key_to_b64,
};

pub type ConnectionKeys = (
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
    zeroize::Zeroizing<[u8; 32]>,
);

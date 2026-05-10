use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::AesKey;

pub fn derive_handshake_key(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"mlkem_handshake_key", &mut *key)
        .expect("32 bytes is valid for HKDF");
    key
}

pub fn derive_initial_master(mlkem_ss: &[u8], x25519_ss: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Vec::with_capacity(mlkem_ss.len() + x25519_ss.len());
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);
    let hkdf = Hkdf::<Sha256>::new(Some(b"initial_master_salt"), &ikm);
    let mut master = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"", &mut *master)
        .expect("32 bytes is valid for HKDF");
    master
}

pub fn derive_cookie_master_key(master: &[u8; 32]) -> AesKey {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut key = [0u8; 32];
    hkdf.expand(b"cookie_master_key", &mut key)
        .expect("32 bytes is valid for HKDF");
    key.into()
}

pub fn derive_connection_keys(master: &[u8; 32], conn_nonce: &[u8; 16]) -> (AesKey, AesKey) {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut info = Vec::with_capacity(16 + 15);
    info.extend_from_slice(conn_nonce);
    info.extend_from_slice(b"connection_keys");
    let mut buf = [0u8; 64];
    hkdf.expand(&info, &mut buf)
        .expect("64 bytes is valid for HKDF");

    let mut upload_key = [0u8; 32];
    let mut download_key = [0u8; 32];
    upload_key.copy_from_slice(&buf[..32]);
    download_key.copy_from_slice(&buf[32..]);
    (upload_key.into(), download_key.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_handshake_key_deterministic() {
        let shared = [0xAAu8; 32];
        let k1 = derive_handshake_key(&shared);
        let k2 = derive_handshake_key(&shared);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_initial_master_deterministic() {
        let ml = [0x11u8; 32];
        let x2 = [0x22u8; 32];
        let m1 = derive_initial_master(&ml, &x2);
        let m2 = derive_initial_master(&ml, &x2);
        assert_eq!(*m1, *m2);
    }

    #[test]
    fn connection_keys_deterministic() {
        let master = [0xBBu8; 32];
        let nonce = [0xCCu8; 16];
        let (up1, dn1) = derive_connection_keys(&master, &nonce);
        let (up2, dn2) = derive_connection_keys(&master, &nonce);
        assert_eq!(up1, up2);
        assert_eq!(dn1, dn2);
    }

    #[test]
    fn connection_keys_different_for_different_nonces() {
        let master = [0xBBu8; 32];
        let n1 = [0xCCu8; 16];
        let n2 = [0xDDu8; 16];
        let (up1, _) = derive_connection_keys(&master, &n1);
        let (up2, _) = derive_connection_keys(&master, &n2);
        assert_ne!(up1, up2);
    }
}

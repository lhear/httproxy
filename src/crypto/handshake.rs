use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub fn derive_handshake_key(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"mlkem_handshake_key", &mut *key)
        .expect("32 bytes is valid for HKDF");
    key
}

pub fn derive_initial_master(mlkem_ss: &[u8], x25519_ss: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(mlkem_ss.len() + x25519_ss.len()));
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);
    let hkdf = Hkdf::<Sha256>::new(Some(b"initial_master_salt"), &ikm);
    let mut master = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"", &mut *master)
        .expect("32 bytes is valid for HKDF");
    master
}

pub fn derive_cookie_stream_key(master: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"cookie_stream_key", &mut *key)
        .expect("32 bytes is valid for HKDF");
    key
}

pub fn derive_connection_keys(master: &[u8; 32], stream_id: &[u8; 16]) -> super::ConnectionKeys {
    let hkdf = Hkdf::<Sha256>::new(None, master);
    let mut info = Vec::with_capacity(16 + 15);
    info.extend_from_slice(stream_id);
    info.extend_from_slice(b"connection_keys");
    let mut buf = Zeroizing::new([0u8; 96]);
    hkdf.expand(&info, &mut *buf)
        .expect("96 bytes is valid for HKDF");

    let mut upload_key = Zeroizing::new([0u8; 32]);
    let mut download_key = Zeroizing::new([0u8; 32]);
    let mut target_key = Zeroizing::new([0u8; 32]);
    upload_key.copy_from_slice(&buf[..32]);
    download_key.copy_from_slice(&buf[32..64]);
    target_key.copy_from_slice(&buf[64..]);
    (upload_key, download_key, target_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_handshake_key_domain_separated() {
        let mut shared = [0xAAu8; 32];
        let k1 = derive_handshake_key(&shared);
        shared[0] ^= 0x01;
        let k2 = derive_handshake_key(&shared);
        assert_ne!(
            *k1, *k2,
            "different shared secrets must derive different keys"
        );
    }

    #[test]
    fn derive_initial_master_domain_separated() {
        let mut ml = [0x11u8; 32];
        let x2 = [0x22u8; 32];
        let m1 = derive_initial_master(&ml, &x2);
        ml[0] ^= 0x01;
        let m2 = derive_initial_master(&ml, &x2);
        assert_ne!(
            *m1, *m2,
            "different ML-KEM secrets must derive different masters"
        );
    }

    #[test]
    fn connection_keys_domain_separated() {
        let mut master = [0xBBu8; 32];
        let nonce = [0xCCu8; 16];
        let (up1, dn1, tg1) = derive_connection_keys(&master, &nonce);
        master[0] ^= 0x01;
        let (up2, dn2, tg2) = derive_connection_keys(&master, &nonce);
        assert_ne!(up1, up2);
        assert_ne!(dn1, dn2);
        assert_ne!(tg1, tg2);
    }

    #[test]
    fn connection_keys_different_for_different_nonces() {
        let master = [0xBBu8; 32];
        let n1 = [0xCCu8; 16];
        let n2 = [0xDDu8; 16];
        let (up1, _, _) = derive_connection_keys(&master, &n1);
        let (up2, _, _) = derive_connection_keys(&master, &n2);
        assert_ne!(up1, up2);
    }
}

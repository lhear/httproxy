use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use zeroize::Zeroizing;

struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub(crate) fn expand_key(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]], out: &mut [u8]) {
    let salt = match salt {
        Some(value) => Salt::new(HKDF_SHA256, value),
        None => Salt::none(HKDF_SHA256),
    };
    let prk = salt.extract(ikm);
    prk.expand(info, OutputLen(out.len()))
        .expect("valid HKDF output length")
        .fill(out)
        .expect("valid HKDF output length");
}

pub fn derive_handshake_key(shared: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_key(None, shared, &[b"mlkem_handshake_key"], &mut *key);
    key
}

pub fn derive_initial_master(mlkem_ss: &[u8], x25519_ss: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(mlkem_ss.len() + x25519_ss.len()));
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);
    let mut master = Zeroizing::new([0u8; 32]);
    expand_key(Some(b"initial_master_salt"), &ikm, &[], &mut *master);
    master
}

pub fn derive_cookie_stream_key(master: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_key(None, master, &[b"cookie_stream_key"], &mut *key);
    key
}

pub fn derive_connection_keys(master: &[u8; 32], stream_id: &[u8; 16]) -> super::ConnectionKeys {
    let mut buf = Zeroizing::new([0u8; 96]);
    expand_key(
        None,
        master,
        &[stream_id.as_slice(), b"connection_keys"],
        &mut *buf,
    );

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
    fn derive_handshake_key_matches_known_vector() {
        let shared = [0xAAu8; 32];
        let expected = [
            0x83, 0xA2, 0x42, 0xB0, 0xA3, 0x80, 0x09, 0x71, 0x5C, 0x8F, 0x1D, 0x63, 0xF5, 0x2A,
            0xBF, 0xAB, 0x2B, 0x8B, 0x45, 0xA0, 0x4C, 0xDB, 0x75, 0x6A, 0x09, 0x73, 0x82, 0x2A,
            0xCB, 0xD9, 0x3F, 0xC1,
        ];
        assert_eq!(*derive_handshake_key(&shared), expected);
    }

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

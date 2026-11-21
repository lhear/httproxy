use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use zeroize::Zeroizing;

struct OutputLen(usize);

impl KeyType for OutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub fn expand_key(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]], out: &mut [u8]) {
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

pub fn derive_handshake_key(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    expand_key(None, shared, &[b"handshake_key"], &mut *key);
    key
}

pub fn derive_initial_master(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut master = Zeroizing::new([0u8; 32]);
    expand_key(Some(b"initial_master_salt"), shared, &[], &mut *master);
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
            0x30, 0x51, 0x37, 0x74, 0x88, 0x65, 0xEF, 0x5B, 0xEE, 0x02, 0x2C, 0x64, 0x53, 0x92,
            0xCE, 0xC0, 0x13, 0x81, 0xB3, 0x3D, 0x2A, 0x55, 0x6E, 0x10, 0x88, 0x24, 0xC5, 0xEB,
            0x0A, 0x97, 0x1C, 0x5A,
        ];
        assert_eq!(*derive_handshake_key(&shared), expected);
    }

    #[test]
    fn derive_initial_master_matches_known_vector() {
        let shared = [0xAAu8; 32];
        let expected = [
            0x29, 0xB4, 0x6D, 0x35, 0x53, 0x11, 0x73, 0x10, 0x48, 0x78, 0xE2, 0xEB, 0x78, 0x9D,
            0x8A, 0x5D, 0x25, 0xF5, 0x53, 0x2C, 0x7D, 0x3A, 0x0D, 0x05, 0x02, 0x9D, 0x6C, 0xBD,
            0x14, 0x40, 0x85, 0x5D,
        ];
        assert_eq!(*derive_initial_master(&shared), expected);
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

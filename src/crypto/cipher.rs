use anyhow::{Result, anyhow};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use rand::Rng;
use std::io;
use zeroize::Zeroizing;

use crate::shaper::FrameCipher;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[inline]
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

#[inline]
fn make_key(key_z: &Zeroizing<[u8; 32]>) -> Result<LessSafeKey> {
    let unbound =
        UnboundKey::new(&AES_256_GCM, &**key_z).map_err(|_| anyhow!("invalid key length"))?;
    Ok(LessSafeKey::new(unbound))
}

#[inline]
fn encrypt_with_cipher(cipher: &LessSafeKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = random_nonce();
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(plaintext);

    let tag = cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut out[NONCE_LEN..],
        )
        .map_err(|_| anyhow!("encryption error"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

#[inline]
fn decrypt_with_cipher(cipher: &LessSafeKey, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let nonce = Nonce::try_assume_unique_for_key(&data[..NONCE_LEN])
        .map_err(|_| anyhow!("invalid nonce length"))?;

    let mut plaintext = data[NONCE_LEN..].to_vec();
    let pt_len = cipher
        .open_in_place(nonce, Aad::empty(), &mut plaintext[..])
        .map_err(|_| anyhow!("decryption error"))?
        .len();
    plaintext.truncate(pt_len);
    Ok(plaintext)
}

#[inline]
pub fn encrypt_bytes(key_z: &Zeroizing<[u8; 32]>, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = make_key(key_z)?;
    encrypt_with_cipher(&cipher, data)
}

#[inline]
pub fn decrypt_bytes(key_z: &Zeroizing<[u8; 32]>, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = make_key(key_z)?;
    decrypt_with_cipher(&cipher, data)
}

pub struct AesFrameCipher {
    key: Zeroizing<[u8; 32]>,
    cipher: LessSafeKey,
}

impl Clone for AesFrameCipher {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(&self.key)
    }
}

impl AesFrameCipher {
    #[inline]
    pub fn new(key_z: &Zeroizing<[u8; 32]>) -> Self {
        let key = Zeroizing::new(**key_z);
        let cipher = make_key(key_z).expect("32 bytes is valid for AES-256-GCM");
        Self { key, cipher }
    }
}

impl FrameCipher for AesFrameCipher {
    #[inline]
    fn encrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        encrypt_with_cipher(&self.cipher, data).map_err(io::Error::other)
    }

    #[inline]
    fn decrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        decrypt_with_cipher(&self.cipher, data).map_err(io::Error::other)
    }

    #[inline]
    fn encrypt_into(&self, data: &[u8], out: &mut bytes::BytesMut) -> io::Result<()> {
        let nonce_bytes = random_nonce();
        out.reserve(NONCE_LEN + data.len() + TAG_LEN);
        out.extend_from_slice(&nonce_bytes);
        let ct_start = out.len();
        out.extend_from_slice(data);
        let tag = self
            .cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::empty(),
                &mut out[ct_start..],
            )
            .map_err(|_| io::Error::other("encryption error"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }

    #[inline]
    fn decrypt_into(&self, data: &[u8], out: &mut bytes::BytesMut) -> io::Result<()> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ciphertext too short",
            ));
        }
        let nonce = Nonce::try_assume_unique_for_key(&data[..NONCE_LEN])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"))?;
        out.reserve(data.len() - NONCE_LEN);
        let pt_start = out.len();
        out.extend_from_slice(&data[NONCE_LEN..]);
        let pt_len = self
            .cipher
            .open_in_place(nonce, Aad::empty(), &mut out[pt_start..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?
            .len();
        out.truncate(pt_start + pt_len);
        Ok(())
    }

    #[inline]
    fn decrypt_in_place(&self, buf: &mut [u8]) -> io::Result<std::ops::Range<usize>> {
        if buf.len() < NONCE_LEN + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ciphertext too short",
            ));
        }
        let nonce = Nonce::try_assume_unique_for_key(&buf[..NONCE_LEN])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"))?;
        let pt_len = self
            .cipher
            .open_in_place(nonce, Aad::empty(), &mut buf[NONCE_LEN..])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?
            .len();
        Ok(NONCE_LEN..NONCE_LEN + pt_len)
    }

    #[inline]
    fn seal_in_place(
        &self,
        out: &mut bytes::BytesMut,
        nonce_start: usize,
        ct_start: usize,
    ) -> io::Result<()> {
        let nonce_bytes = random_nonce();
        out[nonce_start..ct_start].copy_from_slice(&nonce_bytes);
        let tag = self
            .cipher
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::empty(),
                &mut out[ct_start..],
            )
            .map_err(|_| io::Error::other("encryption error"))?;
        out.extend_from_slice(tag.as_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_key() -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(&mut *bytes);
        bytes
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = random_key();
        let plain = b"hello world test frame data";

        let ct = encrypt_bytes(&key, plain).unwrap();
        let pt = decrypt_bytes(&key, &ct).unwrap();
        assert_eq!(pt, plain);

        let cipher = AesFrameCipher::new(&key);
        let frame_ct = cipher.encrypt(plain).unwrap();
        let frame_pt = cipher.decrypt(&frame_ct).unwrap();
        assert_eq!(frame_pt, plain);
    }

    #[test]
    fn decrypt_garbage_fails() {
        let key = random_key();
        assert!(decrypt_bytes(&key, b"too-short").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_decryption() {
        let key = random_key();
        let cipher = AesFrameCipher::new(&key);
        let ct = cipher.encrypt(b"authenticated data").unwrap();
        let mut tampered = ct.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        assert!(cipher.decrypt(&tampered).is_err());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = random_key();
        let key2 = random_key();
        let c1 = AesFrameCipher::new(&key1);
        let c2 = AesFrameCipher::new(&key2);
        let ct = c1.encrypt(b"secret data").unwrap();
        assert!(c2.decrypt(&ct).is_err());
    }

    #[test]
    fn encrypt_into_matches_encrypt() {
        let key = random_key();
        let cipher = AesFrameCipher::new(&key);
        let plain = b"in-place frame payload";

        let mut out = bytes::BytesMut::new();
        cipher.encrypt_into(plain, &mut out).unwrap();
        assert_eq!(out.len(), NONCE_LEN + plain.len() + TAG_LEN);

        let mut pt = bytes::BytesMut::new();
        cipher.decrypt_into(&out, &mut pt).unwrap();
        assert_eq!(&pt[..], plain);
    }
}

use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use anyhow::{Result, anyhow};
use rand::Rng;
use std::io;
use zeroize::Zeroizing;

use crate::shaper::FrameCipher;

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
const EMPTY_AAD: &[u8] = b"";

#[inline]
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

#[inline]
fn encrypt_with_cipher(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = random_nonce();
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(plaintext);

    let tag = cipher
        .encrypt_in_place_detached(
            Nonce::from_slice(&nonce_bytes),
            EMPTY_AAD,
            &mut out[NONCE_LEN..],
        )
        .map_err(|e| anyhow!("encryption error: {e}"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

#[inline]
fn decrypt_with_cipher(cipher: &Aes256Gcm, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let ct_end = data.len() - TAG_LEN;
    let mut plaintext = data[NONCE_LEN..ct_end].to_vec();

    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&data[..NONCE_LEN]),
            EMPTY_AAD,
            &mut plaintext,
            Tag::from_slice(&data[ct_end..]),
        )
        .map_err(|e| anyhow!("decryption error: {e}"))?;
    Ok(plaintext)
}

#[inline]
pub fn encrypt_bytes(key_z: &Zeroizing<[u8; 32]>, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&**key_z).map_err(|_| anyhow!("invalid key length"))?;
    encrypt_with_cipher(&cipher, data)
}

#[inline]
pub fn decrypt_bytes(key_z: &Zeroizing<[u8; 32]>, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&**key_z).map_err(|_| anyhow!("invalid key length"))?;
    decrypt_with_cipher(&cipher, data)
}

pub struct AesFrameCipher {
    key: Zeroizing<[u8; 32]>,
    cipher: Aes256Gcm,
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
        let cipher = Aes256Gcm::new_from_slice(&**key_z).expect("32 bytes is valid for Aes256Gcm");
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
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                EMPTY_AAD,
                &mut out[ct_start..],
            )
            .map_err(|e| io::Error::other(anyhow!("encryption error: {e}")))?;
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
        let ct_end = data.len() - TAG_LEN;
        let ct_len = ct_end - NONCE_LEN;
        out.reserve(ct_len);
        let pt_start = out.len();
        out.extend_from_slice(&data[NONCE_LEN..ct_end]);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&data[..NONCE_LEN]),
                EMPTY_AAD,
                &mut out[pt_start..],
                Tag::from_slice(&data[ct_end..]),
            )
            .map_err(|e| io::Error::other(anyhow!("decryption error: {e}")))?;
        Ok(())
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
            .encrypt_in_place_detached(
                Nonce::from_slice(&nonce_bytes),
                EMPTY_AAD,
                &mut out[ct_start..],
            )
            .map_err(|e| io::Error::other(anyhow!("encryption error: {e}")))?;
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
    }

    #[test]
    fn frame_cipher_roundtrip() {
        let key = random_key();
        let cipher = AesFrameCipher::new(&key);
        let data = b"frame data for cipher test";
        let ct = cipher.encrypt(data).unwrap();
        let pt = cipher.decrypt(&ct).unwrap();
        assert_eq!(pt, data);
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
}

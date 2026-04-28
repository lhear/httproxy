use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use std::io;
use zeroize::Zeroizing;

use super::AesKey;
use crate::shaper::FrameCipher;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
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
fn decrypt_with_cipher(
    cipher: &Aes256Gcm,
    data: &[u8],
    short_err: &'static str,
) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!(short_err));
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

#[allow(dead_code)]
#[inline]
pub fn encrypt_cookie(key: &AesKey, plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(key);
    let encrypted = encrypt_with_cipher(&cipher, plaintext.as_bytes())?;
    Ok(URL_SAFE_NO_PAD.encode(encrypted))
}

#[allow(dead_code)]
#[inline]
pub fn decrypt_cookie(key: &AesKey, ciphertext_b64: &str) -> Result<String> {
    let mut combined = URL_SAFE_NO_PAD.decode(ciphertext_b64.as_bytes())?;
    if combined.len() < NONCE_LEN + TAG_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new(key);
    let ct_len = combined.len() - NONCE_LEN - TAG_LEN;
    let (nonce_bytes, rest) = combined.split_at_mut(NONCE_LEN);
    let (ciphertext, tag_bytes) = rest.split_at_mut(ct_len);

    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce_bytes),
            EMPTY_AAD,
            ciphertext,
            Tag::from_slice(tag_bytes),
        )
        .map_err(|e| anyhow!("decryption error: {e}"))?;

    let result = ciphertext.to_vec();
    String::from_utf8(result).map_err(|e| anyhow!("invalid utf8: {e}"))
}

#[inline]
pub fn encrypt_bytes(key: &AesKey, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    encrypt_with_cipher(&cipher, data)
}

#[inline]
pub fn decrypt_bytes(key: &AesKey, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    decrypt_with_cipher(&cipher, data, "encrypted data too short")
}

pub struct AesFrameCipher {
    key: Zeroizing<[u8; 32]>,
    cipher: Aes256Gcm,
}

impl Clone for AesFrameCipher {
    #[inline]
    fn clone(&self) -> Self {
        Self::new(AesKey::from(*self.key))
    }
}

impl AesFrameCipher {
    #[inline]
    pub fn new(key: AesKey) -> Self {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(key.as_ref());
        let cipher = Aes256Gcm::new(&key);
        Self {
            key: Zeroizing::new(key_bytes),
            cipher,
        }
    }
}

impl FrameCipher for AesFrameCipher {
    #[inline]
    fn encrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        encrypt_with_cipher(&self.cipher, data).map_err(io::Error::other)
    }

    #[inline]
    fn decrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        decrypt_with_cipher(&self.cipher, data, "encrypted frame too short")
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    fn random_key() -> AesKey {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        AesKey::from(bytes)
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
    fn cookie_encrypt_decrypt_roundtrip() {
        let key = random_key();
        let msg = "session-1234";
        let ct = encrypt_cookie(&key, msg).unwrap();
        let pt = decrypt_cookie(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn frame_cipher_roundtrip() {
        let key = random_key();
        let cipher = AesFrameCipher::new(key);
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
    fn decrypt_cookie_invalid_utf8() {
        let key = random_key();
        let junk = URL_SAFE_NO_PAD.encode(b"\xff\xfe\xfd");
        let padded = format!("AAAAQQAAAAAA{}{junk}", "x".repeat(12));
        assert!(decrypt_cookie(&key, &padded).is_err());
    }
}

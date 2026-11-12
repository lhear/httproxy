use anyhow::{Result, anyhow};
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use rand::Rng;
use std::io;
use zeroize::Zeroizing;

use crate::crypto::expand_key;
use crate::shaper::{FrameCipher, HEADER_LEN};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
const OPAQUE_BIT: u8 = 0x80;

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

pub(crate) struct PlainFrameCipher;

impl FrameCipher for PlainFrameCipher {
    #[inline]
    fn encrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(NONCE_LEN + data.len() + TAG_LEN);
        out.extend_from_slice(&[0u8; NONCE_LEN]);
        out.extend_from_slice(data);
        out.extend_from_slice(&[0u8; TAG_LEN]);
        Ok(out)
    }

    #[inline]
    fn decrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too short",
            ));
        }
        Ok(data[NONCE_LEN..data.len() - TAG_LEN].to_vec())
    }
}

pub struct AesFrameCipher {
    cipher: LessSafeKey,
}

impl AesFrameCipher {
    #[inline]
    pub fn new(key_z: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            cipher: make_key(key_z).expect("32 bytes is valid for AES-256-GCM"),
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
        open_in_place_with(&self.cipher, buf)
    }

    #[inline]
    fn seal_in_place(
        &self,
        out: &mut Vec<u8>,
        nonce_start: usize,
        ct_start: usize,
    ) -> io::Result<()> {
        seal_in_place_with(&self.cipher, out, nonce_start, ct_start)
    }
}

#[inline]
fn seal_in_place_with(
    cipher: &LessSafeKey,
    out: &mut Vec<u8>,
    nonce_start: usize,
    ct_start: usize,
) -> io::Result<()> {
    let mut nonce_bytes = random_nonce();
    nonce_bytes[0] &= !OPAQUE_BIT;
    out[nonce_start..ct_start].copy_from_slice(&nonce_bytes);
    let tag = cipher
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
fn open_in_place_with(cipher: &LessSafeKey, buf: &mut [u8]) -> io::Result<std::ops::Range<usize>> {
    if buf.len() < NONCE_LEN + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ciphertext too short",
        ));
    }
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&buf[..NONCE_LEN]);
    let pt_len = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::empty(),
            &mut buf[NONCE_LEN..],
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption error"))?
        .len();
    Ok(NONCE_LEN..NONCE_LEN + pt_len)
}

#[inline]
fn subkey(key: &Zeroizing<[u8; 32]>, label: &[u8]) -> LessSafeKey {
    let mut derived = Zeroizing::new([0u8; 32]);
    expand_key(None, &**key, &[label], &mut *derived);
    make_key(&derived).expect("32 bytes is valid for AES-256-GCM")
}

pub struct StreamCipher {
    data: LessSafeKey,
    mask: LessSafeKey,
    auth: LessSafeKey,
}

impl StreamCipher {
    pub fn new(key_z: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            data: subkey(key_z, b"frame_data_key"),
            mask: subkey(key_z, b"frame_mask_key"),
            auth: subkey(key_z, b"frame_auth_key"),
        }
    }

    #[inline]
    fn mask_block(&self, prefix: &[u8; NONCE_LEN]) -> io::Result<[u8; 16]> {
        let tag = self
            .mask
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*prefix),
                Aad::empty(),
                &mut [],
            )
            .map_err(|_| io::Error::other("encryption error"))?;
        let mut block = [0u8; 16];
        block.copy_from_slice(tag.as_ref());
        Ok(block)
    }

    #[inline]
    fn header_tag(&self, prefix: &[u8; NONCE_LEN], header: &[u8]) -> io::Result<[u8; TAG_LEN]> {
        let mut aad = [0u8; NONCE_LEN + HEADER_LEN];
        aad[..NONCE_LEN].copy_from_slice(prefix);
        aad[NONCE_LEN..].copy_from_slice(header);
        let tag = self
            .auth
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*prefix),
                Aad::from(&aad[..]),
                &mut [],
            )
            .map_err(|_| io::Error::other("encryption error"))?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }
}

impl FrameCipher for StreamCipher {
    #[inline]
    fn encrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        encrypt_with_cipher(&self.data, data).map_err(io::Error::other)
    }

    #[inline]
    fn decrypt(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        decrypt_with_cipher(&self.data, data).map_err(io::Error::other)
    }

    #[inline]
    fn seal_in_place(
        &self,
        out: &mut Vec<u8>,
        nonce_start: usize,
        ct_start: usize,
    ) -> io::Result<()> {
        seal_in_place_with(&self.data, out, nonce_start, ct_start)
    }

    #[inline]
    fn decrypt_in_place(&self, buf: &mut [u8]) -> io::Result<std::ops::Range<usize>> {
        open_in_place_with(&self.data, buf)
    }

    fn seal_frame(
        &self,
        out: &mut Vec<u8>,
        nonce_start: usize,
        ct_start: usize,
        opaque: bool,
    ) -> io::Result<()> {
        if !opaque {
            return seal_in_place_with(&self.data, out, nonce_start, ct_start);
        }
        let mut prefix = random_nonce();
        prefix[0] |= OPAQUE_BIT;
        let block = self.mask_block(&prefix)?;
        let len_at = ct_start + HEADER_LEN - 2;
        let raw_len = u16::from_be_bytes([out[len_at], out[len_at + 1]]) as usize;
        let body_end = ct_start + HEADER_LEN + raw_len;
        if body_end < out.len() {
            rand::rng().fill_bytes(&mut out[body_end..]);
        }
        out[nonce_start..nonce_start + NONCE_LEN].copy_from_slice(&prefix);
        for i in 0..HEADER_LEN {
            out[ct_start + i] ^= block[i];
        }
        let tag = self.header_tag(&prefix, &out[ct_start..ct_start + HEADER_LEN])?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn open_frame(&self, buf: &mut [u8]) -> io::Result<std::ops::Range<usize>> {
        if buf.len() < NONCE_LEN + HEADER_LEN + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too short",
            ));
        }
        if buf[0] & OPAQUE_BIT == 0 {
            return open_in_place_with(&self.data, buf);
        }

        let end = buf.len() - TAG_LEN;
        let mut prefix = [0u8; NONCE_LEN];
        prefix.copy_from_slice(&buf[..NONCE_LEN]);
        let block = self.mask_block(&prefix)?;
        let mut header = [0u8; HEADER_LEN];
        for i in 0..HEADER_LEN {
            header[i] = buf[NONCE_LEN + i] ^ block[i];
        }
        let tag = self.header_tag(&prefix, &buf[NONCE_LEN..NONCE_LEN + HEADER_LEN])?;
        if aws_lc_rs::constant_time::verify_slices_are_equal(tag.as_ref(), &buf[end..]).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame authentication failed",
            ));
        }
        let raw_len = u16::from_be_bytes([header[HEADER_LEN - 2], header[HEADER_LEN - 1]]) as usize;
        if end < NONCE_LEN + HEADER_LEN + raw_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload shorter than declared length",
            ));
        }
        buf[NONCE_LEN..NONCE_LEN + HEADER_LEN].copy_from_slice(&header);
        Ok(NONCE_LEN..NONCE_LEN + HEADER_LEN + raw_len)
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

    fn stream_frame(cipher: &dyn FrameCipher, seq: u64, data: &[u8], plain: bool) -> Vec<u8> {
        let mut frame = vec![0u8; NONCE_LEN];
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        cipher.seal_frame(&mut frame, 0, NONCE_LEN, plain).unwrap();
        frame
    }

    #[test]
    fn frame_mode_lives_in_prefix() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        let data = vec![0x22u8; 64];
        assert_eq!(stream_frame(&cipher, 0, &data, false)[0] & OPAQUE_BIT, 0);
        assert_eq!(
            stream_frame(&cipher, 0, &data, true)[0] & OPAQUE_BIT,
            OPAQUE_BIT
        );
    }

    #[test]
    fn stream_roundtrip_with_opaque_payload() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        let data = vec![0x41u8; 16000];
        let mut frame = stream_frame(&cipher, 3, &data, true);
        let range = cipher.open_frame(&mut frame).unwrap();
        assert_eq!(range.start, NONCE_LEN);
        assert_eq!(&frame[range.start..range.start + 8], &3u64.to_be_bytes());
        assert_eq!(&frame[range.start + HEADER_LEN..range.end], &data[..]);
    }

    #[test]
    fn stream_keeps_sealed_frames_sealed() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        let data = vec![0x11u8; 1024];
        let mut frame = stream_frame(&cipher, 0, &data, false);
        let range = cipher.open_frame(&mut frame).unwrap();
        assert_eq!(&frame[range.start + HEADER_LEN..range.end], &data[..]);
    }

    #[test]
    fn opaque_and_sealed_frames_have_equal_length() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        for len in [0usize, 1, 17, 8191, 8192, 16000] {
            let data = vec![0x33u8; len];
            let sealed = stream_frame(&cipher, 1, &data, false);
            let opaque = stream_frame(&cipher, 1, &data, true);
            assert_eq!(sealed.len(), opaque.len(), "len {len}");
        }
    }

    #[test]
    fn opaque_header_is_masked() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        let data = vec![0x22u8; 9000];
        let frame = stream_frame(&cipher, 5, &data, true);
        let header = &frame[NONCE_LEN..NONCE_LEN + HEADER_LEN];
        assert_ne!(&header[..8], &5u64.to_be_bytes()[..]);
        assert_ne!(&header[8..], &(data.len() as u16).to_be_bytes()[..]);
    }

    #[test]
    fn tampered_opaque_header_rejected() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        let data = vec![0x22u8; 9000];
        let mut frame = stream_frame(&cipher, 5, &data, true);
        frame[NONCE_LEN] ^= 0x01;
        assert!(cipher.open_frame(&mut frame).is_err());
    }

    #[test]
    fn tampered_opaque_tag_rejected() {
        let key = random_key();
        let cipher = StreamCipher::new(&key);
        let data = vec![0x22u8; 9000];
        let mut frame = stream_frame(&cipher, 5, &data, true);
        let last = frame.len() - 1;
        frame[last] ^= 0x80;
        assert!(cipher.open_frame(&mut frame).is_err());
    }

    #[test]
    fn opaque_frame_requires_matching_key() {
        let key1 = random_key();
        let key2 = random_key();
        let sender = StreamCipher::new(&key1);
        let receiver = StreamCipher::new(&key2);
        let data = vec![0x22u8; 9000];
        let mut frame = stream_frame(&sender, 5, &data, true);
        assert!(receiver.open_frame(&mut frame).is_err());
    }
}

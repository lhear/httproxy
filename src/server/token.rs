use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use zeroize::Zeroizing;

use super::Claims;

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const BODY_LEN: usize = 1 + 8 + 2;
const KEY_INFO: &[u8] = b"httproxy-token-v1";

pub const MAX_TOKEN_LEN: usize = 1024;

pub fn key_from_secret(secret: &[u8]) -> LessSafeKey {
    let mut key = Zeroizing::new([0u8; 32]);
    crate::crypto::expand_key(None, secret, &[KEY_INFO], &mut *key);
    let unbound = UnboundKey::new(&AES_256_GCM, &*key).expect("32 bytes is valid for AES-256-GCM");
    LessSafeKey::new(unbound)
}

pub fn issue(key: &LessSafeKey, claims: &Claims) -> String {
    let sub = claims.sub.as_bytes();
    let mut raw = Vec::with_capacity(NONCE_LEN + BODY_LEN + sub.len() + TAG_LEN);

    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    raw.extend_from_slice(&nonce);

    raw.push(VERSION);
    raw.extend_from_slice(&claims.exp.to_be_bytes());
    raw.extend_from_slice(&(sub.len() as u16).to_be_bytes());
    raw.extend_from_slice(sub);

    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut raw[NONCE_LEN..],
        )
        .expect("AES-256-GCM seal cannot fail");
    raw.extend_from_slice(tag.as_ref());
    URL_SAFE_NO_PAD.encode(&raw)
}

pub fn open(key: &LessSafeKey, token: &str) -> Result<Claims, &'static str> {
    if token.len() > MAX_TOKEN_LEN {
        return Err("token too long");
    }

    let mut raw = [0u8; MAX_TOKEN_LEN];
    let len = URL_SAFE_NO_PAD
        .decode_slice(token.as_bytes(), &mut raw)
        .map_err(|_| "invalid encoding")?;

    if len < NONCE_LEN + BODY_LEN + TAG_LEN {
        return Err("token too short");
    }

    let nonce = Nonce::try_assume_unique_for_key(&raw[..NONCE_LEN]).map_err(|_| "invalid nonce")?;
    let body = key
        .open_in_place(nonce, Aad::empty(), &mut raw[NONCE_LEN..len])
        .map_err(|_| "bad tag")?;

    if body[0] != VERSION {
        return Err("unsupported version");
    }

    let exp = u64::from_be_bytes(body[1..9].try_into().unwrap());
    let sub_len = usize::from(u16::from_be_bytes(body[9..11].try_into().unwrap()));
    if body.len() != BODY_LEN + sub_len {
        return Err("bad payload length");
    }

    let sub = std::str::from_utf8(&body[BODY_LEN..]).map_err(|_| "bad subject")?;
    if exp <= crate::unix_now_secs() {
        return Err("expired");
    }

    Ok(Claims {
        sub: sub.to_owned(),
        exp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> LessSafeKey {
        key_from_secret(b"test-secret")
    }

    fn claims(sub: &str, exp: u64) -> Claims {
        Claims {
            sub: sub.to_string(),
            exp,
        }
    }

    #[test]
    fn roundtrip() {
        let exp = crate::unix_now_secs() + 3600;
        let token = issue(&key(), &claims("alice", exp));
        let parsed = open(&key(), &token).unwrap();
        assert_eq!(parsed.sub, "alice");
        assert_eq!(parsed.exp, exp);
    }

    #[test]
    fn subject_is_not_visible_in_the_token() {
        let token = issue(&key(), &claims("alice", crate::unix_now_secs() + 60));
        let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"alice"));
        assert!(!token.contains("alice"));
    }

    #[test]
    fn token_is_shorter_than_jwt() {
        let token = issue(&key(), &claims("admin", 4_102_444_800));
        assert!(
            token.len() <= 64,
            "expected a short token, got {} chars",
            token.len()
        );
        assert!(!token.contains('.'));
        assert!(!token.contains('='));
    }

    #[test]
    fn nonces_differ_between_tokens() {
        let k = key();
        let exp = crate::unix_now_secs() + 3600;
        assert_ne!(
            issue(&k, &claims("alice", exp)),
            issue(&k, &claims("alice", exp))
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let token = issue(&key(), &claims("alice", crate::unix_now_secs() + 60));
        let other = key_from_secret(b"other-secret");
        assert_eq!(open(&other, &token).unwrap_err(), "bad tag");
    }

    #[test]
    fn expired_rejected() {
        let token = issue(&key(), &claims("alice", crate::unix_now_secs()));
        assert_eq!(open(&key(), &token).unwrap_err(), "expired");
    }

    #[test]
    fn tampered_rejected() {
        let exp = crate::unix_now_secs() + 3600;
        for byte in [NONCE_LEN, NONCE_LEN + 1, NONCE_LEN + BODY_LEN] {
            let token = issue(&key(), &claims("alice", exp));
            let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
            raw[byte] ^= 0x01;
            let forged = URL_SAFE_NO_PAD.encode(&raw);
            assert_eq!(open(&key(), &forged).unwrap_err(), "bad tag");
        }
    }

    #[test]
    fn truncated_rejected() {
        let token = issue(&key(), &claims("alice", crate::unix_now_secs() + 60));
        let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        let cut = URL_SAFE_NO_PAD.encode(&raw[..raw.len() - 1]);
        assert_eq!(open(&key(), &cut).unwrap_err(), "bad tag");
    }

    #[test]
    fn malformed_rejected() {
        let k = key();
        assert_eq!(open(&k, "").unwrap_err(), "token too short");
        assert_eq!(open(&k, "!!!!").unwrap_err(), "invalid encoding");
        assert_eq!(open(&k, "AAAA").unwrap_err(), "token too short");

        let long = "A".repeat(MAX_TOKEN_LEN + 1);
        assert_eq!(open(&k, &long).unwrap_err(), "token too long");
    }

    #[test]
    fn bad_payload_length_rejected() {
        let k = key();
        let mut body = vec![VERSION];
        body.extend_from_slice(&(crate::unix_now_secs() + 60).to_be_bytes());
        body.extend_from_slice(&99u16.to_be_bytes());
        body.extend_from_slice(b"alice");

        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let mut raw = nonce.to_vec();
        raw.extend_from_slice(&body);
        let tag = k
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::empty(),
                &mut raw[NONCE_LEN..],
            )
            .unwrap();
        raw.extend_from_slice(tag.as_ref());
        let token = URL_SAFE_NO_PAD.encode(&raw);
        assert_eq!(open(&k, &token).unwrap_err(), "bad payload length");
    }
}

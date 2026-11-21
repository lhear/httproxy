use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;

#[inline]
pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    (secret, public)
}

#[inline]
pub fn diffie_hellman(our_sk: &StaticSecret, their_pk: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
    let shared = our_sk.diffie_hellman(their_pk);
    if !shared.was_contributory() {
        return Err(anyhow!("degenerate X25519 public key"));
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

pub fn public_key_from_slice(bytes: &[u8]) -> Result<PublicKey> {
    Ok(PublicKey::from(owned_key(bytes, "public key")?))
}

pub fn private_key_to_b64(sk: &StaticSecret) -> String {
    URL_SAFE_NO_PAD.encode(sk.to_bytes())
}

pub fn public_key_to_b64(pk: &PublicKey) -> String {
    URL_SAFE_NO_PAD.encode(pk.as_bytes())
}

pub fn b64_to_private_key(s: &str) -> Result<StaticSecret> {
    Ok(StaticSecret::from(decode_key(s, "private key")?))
}

pub fn b64_to_public_key(s: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(decode_key(s, "public key")?))
}

fn decode_key(s: &str, what: &str) -> Result<[u8; KEY_LEN]> {
    let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(s.as_bytes())?);
    owned_key(&raw, what)
}

fn owned_key(bytes: &[u8], what: &str) -> Result<[u8; KEY_LEN]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("X25519 {what} must be {KEY_LEN} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffie_hellman_agreement() {
        let (a_sk, a_pk) = generate_keypair();
        let (b_sk, b_pk) = generate_keypair();
        assert_eq!(
            *diffie_hellman(&a_sk, &b_pk).unwrap(),
            *diffie_hellman(&b_sk, &a_pk).unwrap()
        );
    }

    #[test]
    fn rejects_low_order_public_key() {
        let (sk, _) = generate_keypair();
        assert!(diffie_hellman(&sk, &PublicKey::from([0u8; KEY_LEN])).is_err());
    }

    #[test]
    fn key_serialization_roundtrip() {
        let (sk, pk) = generate_keypair();
        let sk2 = b64_to_private_key(&private_key_to_b64(&sk)).unwrap();
        let pk2 = b64_to_public_key(&public_key_to_b64(&pk)).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(pk, pk2);
    }

    #[test]
    fn rejects_malformed_keys() {
        assert!(b64_to_private_key("abc").is_err());
        assert!(b64_to_public_key("abc").is_err());
        assert!(public_key_from_slice(&[0u8; KEY_LEN - 1]).is_err());
    }
}

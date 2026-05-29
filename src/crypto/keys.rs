use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto_common::Key;
use ml_kem::{
    Ciphertext, DecapsulationKey, EncapsulationKey, MlKem768,
    kem::{Decapsulate, Encapsulate},
};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

const X25519_KEY_LEN: usize = 32;
const X25519_B64_LEN: usize = 43;

#[inline]
pub fn generate_keypair() -> (StaticSecret, X25519PublicKey) {
    let secret = StaticSecret::random();
    let public = X25519PublicKey::from(&secret);
    (secret, public)
}

#[inline]
fn encode_fixed_32(bytes: &[u8; X25519_KEY_LEN]) -> String {
    let mut out = String::with_capacity(X25519_B64_LEN);
    URL_SAFE_NO_PAD.encode_string(bytes, &mut out);
    out
}

#[inline]
fn decode_fixed_32(s: &str) -> Result<[u8; X25519_KEY_LEN]> {
    let mut out = [0u8; X25519_KEY_LEN];
    let decoded = URL_SAFE_NO_PAD.decode(s.as_bytes())?;
    if decoded.len() != X25519_KEY_LEN {
        return Err(anyhow!("invalid key length"));
    }
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[inline]
pub fn public_key_to_b64(pk: &X25519PublicKey) -> String {
    encode_fixed_32(pk.as_bytes())
}

#[inline]
pub fn private_key_to_b64(sk: &StaticSecret) -> String {
    encode_fixed_32(&sk.to_bytes())
}

#[inline]
pub fn b64_to_public_key(s: &str) -> Result<X25519PublicKey> {
    Ok(X25519PublicKey::from(decode_fixed_32(s)?))
}

#[inline]
pub fn b64_to_private_key(s: &str) -> Result<StaticSecret> {
    Ok(StaticSecret::from(decode_fixed_32(s)?))
}

#[inline]
pub fn diffie_hellman(our_sk: &StaticSecret, their_pk: &X25519PublicKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(*our_sk.diffie_hellman(their_pk).as_bytes())
}

pub fn bytes_to_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>> {
    let key: Key<EncapsulationKey<MlKem768>> = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid encapsulation key length"))?;
    EncapsulationKey::new(&key).map_err(|_| anyhow!("invalid encapsulation key"))
}

pub fn generate_mlkem_keypair() -> (DecapsulationKey<MlKem768>, EncapsulationKey<MlKem768>) {
    use ml_kem::kem::Kem;
    <MlKem768 as Kem>::generate_keypair_from_rng(&mut rand::rng())
}

pub fn mlkem_encapsulate(
    pk: &EncapsulationKey<MlKem768>,
) -> (Ciphertext<MlKem768>, Zeroizing<Vec<u8>>) {
    let (ct, ss) = pk.encapsulate_with_rng(&mut rand::rng());
    let ss_bytes: &[u8] = &ss;
    (ct, Zeroizing::new(ss_bytes.to_vec()))
}

pub fn mlkem_decapsulate(
    sk: &DecapsulationKey<MlKem768>,
    ct: &Ciphertext<MlKem768>,
) -> Zeroizing<Vec<u8>> {
    let ss = sk.decapsulate(ct);
    let ss_bytes: &[u8] = &ss;
    Zeroizing::new(ss_bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrip() {
        let (sk, pk) = generate_keypair();
        let b64_pk = public_key_to_b64(&pk);
        let b64_sk = private_key_to_b64(&sk);
        assert_eq!(b64_pk.len(), X25519_B64_LEN);
        assert_eq!(b64_sk.len(), X25519_B64_LEN);

        let pk2 = b64_to_public_key(&b64_pk).unwrap();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());

        let sk2 = b64_to_private_key(&b64_sk).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn diffie_hellman_agreement() {
        let (a_sk, a_pk) = generate_keypair();
        let (b_sk, b_pk) = generate_keypair();
        let ss_a = diffie_hellman(&a_sk, &b_pk);
        let ss_b = diffie_hellman(&b_sk, &a_pk);
        assert_eq!(*ss_a, *ss_b);
    }

    #[test]
    fn mlkem_roundtrip() {
        let (sk, pk) = generate_mlkem_keypair();
        let (ct, ss_enc) = mlkem_encapsulate(&pk);
        let ss_dec = mlkem_decapsulate(&sk, &ct);
        assert_eq!(*ss_enc, *ss_dec);
    }

    #[test]
    fn b64_invalid_length_rejected() {
        assert!(b64_to_public_key("abc").is_err());
        assert!(b64_to_private_key("abc").is_err());
    }
}

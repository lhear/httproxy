use anyhow::{Result, anyhow};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const X25519_KEY_LEN: usize = 32;
const X25519_B64_LEN: usize = 43;

#[inline]
pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
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
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(s.as_bytes())?);
    if decoded.len() != X25519_KEY_LEN {
        return Err(anyhow!("invalid key length"));
    }
    out.copy_from_slice(&decoded);
    Ok(out)
}

#[inline]
pub fn public_key_to_b64(pk: &PublicKey) -> String {
    encode_fixed_32(pk.as_bytes())
}

#[inline]
pub fn private_key_to_b64(sk: &StaticSecret) -> String {
    encode_fixed_32(&sk.to_bytes())
}

#[inline]
pub fn b64_to_public_key(s: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(decode_fixed_32(s)?))
}

#[inline]
pub fn b64_to_private_key(s: &str) -> Result<StaticSecret> {
    Ok(StaticSecret::from(decode_fixed_32(s)?))
}

#[inline]
pub fn diffie_hellman(our_sk: &StaticSecret, their_pk: &PublicKey) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(*our_sk.diffie_hellman(their_pk).as_bytes())
}

pub fn generate_mlkem_keypair() -> Result<(DecapsulationKey, EncapsulationKey)> {
    let sk = DecapsulationKey::generate(&ML_KEM_768)
        .map_err(|_| anyhow!("ML-KEM key generation failed"))?;
    let pk = sk
        .encapsulation_key()
        .map_err(|_| anyhow!("ML-KEM encapsulation key unavailable"))?;
    Ok((sk, pk))
}

pub fn mlkem_public_key_bytes(pk: &EncapsulationKey) -> Result<Vec<u8>> {
    let bytes = pk
        .key_bytes()
        .map_err(|_| anyhow!("ML-KEM public key export failed"))?;
    Ok(bytes.as_ref().to_vec())
}

pub fn bytes_to_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey> {
    EncapsulationKey::new(&ML_KEM_768, bytes).map_err(|_| anyhow!("invalid encapsulation key"))
}

pub fn mlkem_encapsulate(
    pk: &EncapsulationKey,
) -> Result<(Ciphertext<'static>, Zeroizing<Vec<u8>>)> {
    let (ct, ss) = pk
        .encapsulate()
        .map_err(|_| anyhow!("ML-KEM encapsulation failed"))?;
    Ok((ct, Zeroizing::new(ss.as_ref().to_vec())))
}

pub fn mlkem_decapsulate(sk: &DecapsulationKey, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let ss = sk
        .decapsulate(Ciphertext::from(ct))
        .map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;
    Ok(Zeroizing::new(ss.as_ref().to_vec()))
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
        let (sk, pk) = generate_mlkem_keypair().unwrap();
        let bytes = mlkem_public_key_bytes(&pk).unwrap();
        assert_eq!(bytes.len(), 1184);

        let pk2 = bytes_to_encapsulation_key(&bytes).unwrap();
        let (ct, ss_enc) = mlkem_encapsulate(&pk2).unwrap();
        assert_eq!(ct.as_ref().len(), 1088);

        let ss_dec = mlkem_decapsulate(&sk, ct.as_ref()).unwrap();
        assert_eq!(*ss_enc, *ss_dec);
    }

    #[test]
    fn mlkem_rejects_bad_public_key() {
        assert!(bytes_to_encapsulation_key(&[0u8; 17]).is_err());
    }

    #[test]
    fn mlkem_rejects_bad_ciphertext() {
        let (sk, _) = generate_mlkem_keypair().unwrap();
        assert!(mlkem_decapsulate(&sk, &[0u8; 17]).is_err());
    }

    #[test]
    fn b64_invalid_length_rejected() {
        assert!(b64_to_public_key("abc").is_err());
        assert!(b64_to_private_key("abc").is_err());
    }
}

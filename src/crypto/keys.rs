use anyhow::{Result, anyhow};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[inline]
pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    (secret, public)
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

pub fn mlkem_public_key_to_b64(pk: &EncapsulationKey) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(mlkem_public_key_bytes(pk)?))
}

pub fn b64_to_mlkem_public_key(s: &str) -> Result<EncapsulationKey> {
    let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(s.as_bytes())?);
    EncapsulationKey::new(&ML_KEM_768, &raw).map_err(|_| anyhow!("invalid ML-KEM public key"))
}

pub fn mlkem_private_key_to_b64(sk: &DecapsulationKey) -> Result<String> {
    let bytes = sk
        .key_bytes()
        .map_err(|_| anyhow!("ML-KEM private key export failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

pub fn b64_to_mlkem_private_key(s: &str) -> Result<DecapsulationKey> {
    let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(s.as_bytes())?);
    DecapsulationKey::new(&ML_KEM_768, &raw).map_err(|_| anyhow!("invalid ML-KEM private key"))
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
    fn mlkem_key_serialization_roundtrip() {
        let (sk, pk) = generate_mlkem_keypair().unwrap();
        let pk_b64 = mlkem_public_key_to_b64(&pk).unwrap();
        let sk_b64 = mlkem_private_key_to_b64(&sk).unwrap();

        let pk2 = b64_to_mlkem_public_key(&pk_b64).unwrap();
        let sk2 = b64_to_mlkem_private_key(&sk_b64).unwrap();
        assert_eq!(
            mlkem_public_key_bytes(&pk).unwrap(),
            mlkem_public_key_bytes(&pk2).unwrap()
        );

        let (ct, ss_enc) = mlkem_encapsulate(&pk2).unwrap();
        let ss_dec = mlkem_decapsulate(&sk2, ct.as_ref()).unwrap();
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
    fn mlkem_b64_rejects_bad_keys() {
        assert!(b64_to_mlkem_public_key("abc").is_err());
        assert!(b64_to_mlkem_private_key("abc").is_err());
    }
}

//! ECDH-ES key agreement algorithms for JWE (RFC 7518 §4.6):
//! [`EcdhEs`], [`EcdhEsA128Kw`], [`EcdhEsA192Kw`], [`EcdhEsA256Kw`].
//!
//! Supports P-256 and P-384 curves. The recipient's static public key is the
//! encryption key; the ephemeral public key is transmitted in the `epk` header.

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

pub use no_way_jose_core;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use no_way_jose_core::__private::Sealed;
use no_way_jose_core::JoseError;
use no_way_jose_core::jwe_algorithm::{
    JweKeyManagement, KeyDecryptor, KeyEncryptionResult, KeyEncryptor,
};
use no_way_jose_core::jwk::{EcParams, Jwk, JwkKeyConvert, JwkParams};
use no_way_jose_core::key::{Decrypting, Encrypting, HasKey};
use p256::elliptic_curve::sec1::ToSec1Point;

mod concat_kdf;
mod curve;
mod epk;

use concat_kdf::concat_kdf;
use epk::EpkFields;

/// ECDH-ES direct key agreement — the derived key IS the CEK.
#[derive(Clone, Copy, Debug, Default)]
pub struct EcdhEs;

/// ECDH-ES + AES-128 key wrapping.
#[derive(Clone, Copy, Debug, Default)]
pub struct EcdhEsA128Kw;

/// ECDH-ES + AES-192 key wrapping.
#[derive(Clone, Copy, Debug, Default)]
pub struct EcdhEsA192Kw;

/// ECDH-ES + AES-256 key wrapping.
#[derive(Clone, Copy, Debug, Default)]
pub struct EcdhEsA256Kw;

impl Sealed for EcdhEs {}
impl Sealed for EcdhEsA128Kw {}
impl Sealed for EcdhEsA192Kw {}
impl Sealed for EcdhEsA256Kw {}

impl JweKeyManagement for EcdhEs {
    const ALG: &'static str = "ECDH-ES";
}
impl JweKeyManagement for EcdhEsA128Kw {
    const ALG: &'static str = "ECDH-ES+A128KW";
}
impl JweKeyManagement for EcdhEsA192Kw {
    const ALG: &'static str = "ECDH-ES+A192KW";
}
impl JweKeyManagement for EcdhEsA256Kw {
    const ALG: &'static str = "ECDH-ES+A256KW";
}

/// Encryption key: the recipient's public key on a supported curve.
pub enum EcPublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
}

/// Decryption key: the recipient's private key.
pub enum EcPrivateKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
}

fn ecdh_encrypt(
    recipient_pub: &EcPublicKey,
    alg: &str,
    cek_len: usize,
    wrap_key_len: Option<usize>,
) -> Result<KeyEncryptionResult, JoseError> {
    let (shared_secret, epk_fields) = match recipient_pub {
        EcPublicKey::P256(pub_key) => curve::p256_ecdh_ephemeral(pub_key)?,
        EcPublicKey::P384(pub_key) => curve::p384_ecdh_ephemeral(pub_key)?,
    };

    let derived_key_len = wrap_key_len.unwrap_or(cek_len);
    let derived_key = concat_kdf(&shared_secret, alg, derived_key_len);

    let (encrypted_key, cek) = if wrap_key_len.is_some() {
        let mut cek = vec![0u8; cek_len];
        getrandom::fill(&mut cek).map_err(|_| JoseError::CryptoError)?;
        let wrapped = aes_kw_wrap(&derived_key, &cek)?;
        (wrapped, cek)
    } else {
        (Vec::new(), derived_key)
    };

    let epk_json = epk_fields.to_json_bytes();
    let extra_headers = alloc::vec![(String::from("epk"), epk_json)];

    Ok(KeyEncryptionResult {
        encrypted_key,
        cek,
        extra_headers,
    })
}

fn ecdh_decrypt(
    recipient_priv: &EcPrivateKey,
    encrypted_key: &[u8],
    header: &[u8],
    alg: &str,
    cek_len: usize,
    wrap_key_len: Option<usize>,
) -> Result<Vec<u8>, JoseError> {
    let epk_fields = EpkFields::from_header(header)?;

    let shared_secret = match recipient_priv {
        EcPrivateKey::P256(secret_key) => {
            let peer_pub = epk_fields.to_p256_public_key()?;
            curve::p256_ecdh_decrypt(secret_key, &peer_pub)
        }
        EcPrivateKey::P384(secret_key) => {
            let peer_pub = epk_fields.to_p384_public_key()?;
            curve::p384_ecdh_decrypt(secret_key, &peer_pub)
        }
    };

    let derived_key_len = wrap_key_len.unwrap_or(cek_len);
    let derived_key = concat_kdf(&shared_secret, alg, derived_key_len);

    if wrap_key_len.is_some() {
        aes_kw_unwrap(&derived_key, encrypted_key)
    } else {
        if !encrypted_key.is_empty() {
            return Err(JoseError::InvalidToken(
                "ECDH-ES: encrypted_key must be empty for direct agreement",
            ));
        }
        Ok(derived_key)
    }
}

fn aes_kw_wrap(kek_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JoseError> {
    use aes_kw::KeyInit;
    let mut out = vec![0u8; plaintext.len() + aes_kw::IV_LEN];
    macro_rules! wrap {
        ($ty:ty) => {
            <$ty>::new_from_slice(kek_bytes)
                .map_err(|_| JoseError::InvalidKey)?
                .wrap_key(plaintext, &mut out)
                .map_err(|_| JoseError::CryptoError)
        };
    }
    match kek_bytes.len() {
        16 => wrap!(aes_kw::KwAes128),
        24 => wrap!(aes_kw::KwAes192),
        32 => wrap!(aes_kw::KwAes256),
        _ => return Err(JoseError::InvalidKey),
    }?;
    Ok(out)
}

fn aes_kw_unwrap(kek_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JoseError> {
    use aes_kw::KeyInit;
    if ciphertext.len() < aes_kw::IV_LEN {
        return Err(JoseError::InvalidToken("encrypted key too short"));
    }
    let mut out = vec![0u8; ciphertext.len() - aes_kw::IV_LEN];
    macro_rules! unwrap {
        ($ty:ty) => {
            <$ty>::new_from_slice(kek_bytes)
                .map_err(|_| JoseError::InvalidKey)?
                .unwrap_key(ciphertext, &mut out)
                .map_err(|_| JoseError::CryptoError)
        };
    }
    match kek_bytes.len() {
        16 => unwrap!(aes_kw::KwAes128),
        24 => unwrap!(aes_kw::KwAes192),
        32 => unwrap!(aes_kw::KwAes256),
        _ => return Err(JoseError::InvalidKey),
    }?;
    Ok(out)
}

macro_rules! ecdh_es_impl {
    ($name:ty, $wrap_key_len:expr) => {
        impl HasKey<Encrypting> for $name {
            type Key = EcPublicKey;
        }

        impl HasKey<Decrypting> for $name {
            type Key = EcPrivateKey;
        }

        impl KeyEncryptor for $name {
            fn encrypt_cek(
                key: &EcPublicKey,
                cek_len: usize,
            ) -> Result<KeyEncryptionResult, JoseError> {
                ecdh_encrypt(key, <$name>::ALG, cek_len, $wrap_key_len)
            }
        }

        impl KeyDecryptor for $name {
            fn decrypt_cek(
                key: &EcPrivateKey,
                encrypted_key: &[u8],
                header: &[u8],
                cek_len: usize,
            ) -> Result<Vec<u8>, JoseError> {
                ecdh_decrypt(
                    key,
                    encrypted_key,
                    header,
                    <$name>::ALG,
                    cek_len,
                    $wrap_key_len,
                )
            }
        }
    };
}

ecdh_es_impl!(EcdhEsA128Kw, Some(16));
ecdh_es_impl!(EcdhEsA192Kw, Some(24));
ecdh_es_impl!(EcdhEsA256Kw, Some(32));

// ECDH-ES direct needs special handling: cek_len comes from the CE algorithm,
// not from encrypted_key.len() (which is 0 for direct agreement).
impl HasKey<Encrypting> for EcdhEs {
    type Key = EcPublicKey;
}

impl HasKey<Decrypting> for EcdhEs {
    type Key = EcPrivateKey;
}

impl KeyEncryptor for EcdhEs {
    fn encrypt_cek(key: &EcPublicKey, cek_len: usize) -> Result<KeyEncryptionResult, JoseError> {
        ecdh_encrypt(key, "ECDH-ES", cek_len, None)
    }
}

impl KeyDecryptor for EcdhEs {
    fn decrypt_cek(
        key: &EcPrivateKey,
        encrypted_key: &[u8],
        header: &[u8],
        cek_len: usize,
    ) -> Result<Vec<u8>, JoseError> {
        ecdh_decrypt(key, encrypted_key, header, "ECDH-ES", cek_len, None)
    }
}

fn ec_pubkey_to_jwk(key: &EcPublicKey, alg: &str) -> Jwk {
    let (crv, x, y) = match key {
        EcPublicKey::P256(pk) => {
            let point = pk.to_sec1_point(false);
            (
                "P-256",
                point.x().unwrap().to_vec(),
                point.y().unwrap().to_vec(),
            )
        }
        EcPublicKey::P384(pk) => {
            let point = pk.to_sec1_point(false);
            (
                "P-384",
                point.x().unwrap().to_vec(),
                point.y().unwrap().to_vec(),
            )
        }
    };
    Jwk {
        kty: "EC".into(),
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        params: JwkParams::Ec(EcParams {
            crv: String::from(crv),
            x,
            y,
            d: None,
        }),
    }
}

fn ec_privkey_to_jwk(key: &EcPrivateKey, alg: &str) -> Jwk {
    let (crv, x, y, d) = match key {
        EcPrivateKey::P256(sk) => {
            let pk = sk.public_key();
            let point = pk.to_sec1_point(false);
            (
                "P-256",
                point.x().unwrap().to_vec(),
                point.y().unwrap().to_vec(),
                sk.to_bytes().to_vec(),
            )
        }
        EcPrivateKey::P384(sk) => {
            let pk = sk.public_key();
            let point = pk.to_sec1_point(false);
            (
                "P-384",
                point.x().unwrap().to_vec(),
                point.y().unwrap().to_vec(),
                sk.to_bytes().to_vec(),
            )
        }
    };
    Jwk {
        kty: "EC".into(),
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        params: JwkParams::Ec(EcParams {
            crv: String::from(crv),
            x,
            y,
            d: Some(d),
        }),
    }
}

fn ec_pubkey_from_jwk(jwk: &Jwk, expected_alg: &str) -> Result<EcPublicKey, JoseError> {
    if jwk.kty != "EC" {
        return Err(JoseError::InvalidKey);
    }
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(JoseError::InvalidKey);
    }
    match &jwk.params {
        JwkParams::Ec(p) => match p.crv.as_str() {
            "P-256" => {
                let mut sec1 = Vec::with_capacity(1 + p.x.len() + p.y.len());
                sec1.push(0x04);
                sec1.extend_from_slice(&p.x);
                sec1.extend_from_slice(&p.y);
                let pk =
                    p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| JoseError::InvalidKey)?;
                Ok(EcPublicKey::P256(pk))
            }
            "P-384" => {
                let mut sec1 = Vec::with_capacity(1 + p.x.len() + p.y.len());
                sec1.push(0x04);
                sec1.extend_from_slice(&p.x);
                sec1.extend_from_slice(&p.y);
                let pk =
                    p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| JoseError::InvalidKey)?;
                Ok(EcPublicKey::P384(pk))
            }
            _ => Err(JoseError::InvalidKey),
        },
        _ => Err(JoseError::InvalidKey),
    }
}

fn ec_privkey_from_jwk(jwk: &Jwk, expected_alg: &str) -> Result<EcPrivateKey, JoseError> {
    if jwk.kty != "EC" {
        return Err(JoseError::InvalidKey);
    }
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(JoseError::InvalidKey);
    }
    match &jwk.params {
        JwkParams::Ec(p) => {
            let d = p.d.as_ref().ok_or(JoseError::InvalidKey)?;
            match p.crv.as_str() {
                "P-256" => {
                    let sk = p256::SecretKey::from_slice(d).map_err(|_| JoseError::InvalidKey)?;
                    Ok(EcPrivateKey::P256(sk))
                }
                "P-384" => {
                    let sk = p384::SecretKey::from_slice(d).map_err(|_| JoseError::InvalidKey)?;
                    Ok(EcPrivateKey::P384(sk))
                }
                _ => Err(JoseError::InvalidKey),
            }
        }
        _ => Err(JoseError::InvalidKey),
    }
}

macro_rules! ecdh_es_jwk_impls {
    ($name:ty, $alg:literal) => {
        impl JwkKeyConvert<Encrypting> for $name {
            fn key_to_jwk(key: &EcPublicKey) -> Jwk {
                ec_pubkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<EcPublicKey, JoseError> {
                ec_pubkey_from_jwk(jwk, $alg)
            }
        }
        impl JwkKeyConvert<Decrypting> for $name {
            fn key_to_jwk(key: &EcPrivateKey) -> Jwk {
                ec_privkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<EcPrivateKey, JoseError> {
                ec_privkey_from_jwk(jwk, $alg)
            }
        }
    };
}

ecdh_es_jwk_impls!(EcdhEs, "ECDH-ES");
ecdh_es_jwk_impls!(EcdhEsA128Kw, "ECDH-ES+A128KW");
ecdh_es_jwk_impls!(EcdhEsA192Kw, "ECDH-ES+A192KW");
ecdh_es_jwk_impls!(EcdhEsA256Kw, "ECDH-ES+A256KW");

pub mod ecdh_es {
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::EcdhEs>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::EcdhEs>;

    #[must_use]
    pub fn encryption_key(public_key: super::EcPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn decryption_key(private_key: super::EcPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod ecdh_es_a128kw {
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::EcdhEsA128Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::EcdhEsA128Kw>;

    #[must_use]
    pub fn encryption_key(public_key: super::EcPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn decryption_key(private_key: super::EcPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod ecdh_es_a192kw {
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::EcdhEsA192Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::EcdhEsA192Kw>;

    #[must_use]
    pub fn encryption_key(public_key: super::EcPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn decryption_key(private_key: super::EcPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod ecdh_es_a256kw {
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::EcdhEsA256Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::EcdhEsA256Kw>;

    #[must_use]
    pub fn encryption_key(public_key: super::EcPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn decryption_key(private_key: super::EcPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

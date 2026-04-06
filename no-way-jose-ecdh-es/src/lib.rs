//! ECDH-ES key agreement algorithms for JWE (RFC 7518 §4.6, RFC 8037 for OKP):
//! [`EcdhEs`], [`EcdhEsA128Kw`], [`EcdhEsA192Kw`], [`EcdhEsA256Kw`].
//!
//! Supports P-256, P-384, and X25519. The recipient's static public key is the
//! encryption key; the ephemeral public key is transmitted in the `epk` header.

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::__private::Sealed;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{
    JweKeyManagement, KeyDecryptor, KeyEncryptionResult, KeyEncryptor,
};
use no_way_jose_core::jwk::{
    EcCurve, EcParams, Jwk, JwkKeyConvert, JwkParams, OkpCurve, OkpParams,
};
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
    X25519(x25519_dalek::PublicKey),
}

/// Decryption key: the recipient's private key.
pub enum EcPrivateKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    X25519(x25519_dalek::StaticSecret),
}

fn ecdh_encrypt(
    recipient_pub: &EcPublicKey,
    alg: &str,
    cek_len: usize,
    wrap_key_len: Option<usize>,
) -> JoseResult<KeyEncryptionResult> {
    let (shared_secret, epk_fields) = match recipient_pub {
        EcPublicKey::P256(pub_key) => curve::p256_ecdh_ephemeral(pub_key),
        EcPublicKey::P384(pub_key) => curve::p384_ecdh_ephemeral(pub_key),
        EcPublicKey::X25519(pub_key) => Ok(curve::x25519_ecdh_ephemeral(pub_key)),
    }?;

    let derived_key_len = wrap_key_len.unwrap_or(cek_len);
    let derived_key = concat_kdf(&shared_secret, alg, derived_key_len);

    let (encrypted_key, cek) = if wrap_key_len.is_some() {
        let mut cek = vec![0u8; cek_len];
        getrandom::fill(&mut cek).map_err(|_| Report::new(JoseError::CryptoError))?;
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
) -> JoseResult<Vec<u8>> {
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
        EcPrivateKey::X25519(secret_key) => {
            let peer_pub = epk_fields.to_x25519_public_key()?;
            curve::x25519_ecdh_decrypt(secret_key, &peer_pub)
        }
    };

    let derived_key_len = wrap_key_len.unwrap_or(cek_len);
    let derived_key = concat_kdf(&shared_secret, alg, derived_key_len);

    if wrap_key_len.is_some() {
        aes_kw_unwrap(&derived_key, encrypted_key)
    } else {
        if !encrypted_key.is_empty() {
            return Err(Report::new(JoseError::MalformedToken));
        }
        Ok(derived_key)
    }
}

fn aes_kw_wrap(kek_bytes: &[u8], plaintext: &[u8]) -> JoseResult<Vec<u8>> {
    use aes_kw::KeyInit;
    let mut out = vec![0u8; plaintext.len() + aes_kw::IV_LEN];
    macro_rules! wrap {
        ($ty:ty) => {
            <$ty>::new_from_slice(kek_bytes)
                .map_err(|_| Report::new(JoseError::InvalidKey))?
                .wrap_key(plaintext, &mut out)
                .map_err(|_| Report::new(JoseError::CryptoError))
        };
    }
    match kek_bytes.len() {
        16 => wrap!(aes_kw::KwAes128),
        24 => wrap!(aes_kw::KwAes192),
        32 => wrap!(aes_kw::KwAes256),
        _ => return Err(Report::new(JoseError::InvalidKey)),
    }?;
    Ok(out)
}

fn aes_kw_unwrap(kek_bytes: &[u8], ciphertext: &[u8]) -> JoseResult<Vec<u8>> {
    use aes_kw::KeyInit;
    if ciphertext.len() < aes_kw::IV_LEN {
        return Err(Report::new(JoseError::MalformedToken));
    }
    let mut out = vec![0u8; ciphertext.len() - aes_kw::IV_LEN];
    macro_rules! unwrap {
        ($ty:ty) => {
            <$ty>::new_from_slice(kek_bytes)
                .map_err(|_| Report::new(JoseError::InvalidKey))?
                .unwrap_key(ciphertext, &mut out)
                .map_err(|_| Report::new(JoseError::CryptoError))
        };
    }
    match kek_bytes.len() {
        16 => unwrap!(aes_kw::KwAes128),
        24 => unwrap!(aes_kw::KwAes192),
        32 => unwrap!(aes_kw::KwAes256),
        _ => return Err(Report::new(JoseError::InvalidKey)),
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
            fn encrypt_cek(key: &EcPublicKey, cek_len: usize) -> JoseResult<KeyEncryptionResult> {
                ecdh_encrypt(key, <$name>::ALG, cek_len, $wrap_key_len)
            }
        }

        impl KeyDecryptor for $name {
            fn decrypt_cek(
                key: &EcPrivateKey,
                encrypted_key: &[u8],
                header: &[u8],
                cek_len: usize,
            ) -> JoseResult<Vec<u8>> {
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
    fn encrypt_cek(key: &EcPublicKey, cek_len: usize) -> JoseResult<KeyEncryptionResult> {
        ecdh_encrypt(key, "ECDH-ES", cek_len, None)
    }
}

impl KeyDecryptor for EcdhEs {
    fn decrypt_cek(
        key: &EcPrivateKey,
        encrypted_key: &[u8],
        header: &[u8],
        cek_len: usize,
    ) -> JoseResult<Vec<u8>> {
        ecdh_decrypt(key, encrypted_key, header, "ECDH-ES", cek_len, None)
    }
}

fn ec_pubkey_to_jwk(key: &EcPublicKey, alg: &str) -> Jwk {
    match key {
        EcPublicKey::X25519(pk) => Jwk {
            kid: None,
            alg: Some(alg.into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Okp(OkpParams {
                crv: OkpCurve::X25519,
                x: pk.as_bytes().to_vec(),
                d: None,
            }),
        },
        EcPublicKey::P256(pk) => {
            let point = pk.to_sec1_point(false);
            Jwk {
                kid: None,
                alg: Some(alg.into()),
                use_: None,
                key_ops: None,
                key: JwkParams::Ec(EcParams {
                    crv: EcCurve::P256,
                    x: point.x().unwrap().to_vec(),
                    y: point.y().unwrap().to_vec(),
                    d: None,
                }),
            }
        }
        EcPublicKey::P384(pk) => {
            let point = pk.to_sec1_point(false);
            Jwk {
                kid: None,
                alg: Some(alg.into()),
                use_: None,
                key_ops: None,
                key: JwkParams::Ec(EcParams {
                    crv: EcCurve::P384,
                    x: point.x().unwrap().to_vec(),
                    y: point.y().unwrap().to_vec(),
                    d: None,
                }),
            }
        }
    }
}

fn ec_privkey_to_jwk(key: &EcPrivateKey, alg: &str) -> Jwk {
    match key {
        EcPrivateKey::X25519(sk) => {
            let pk = x25519_dalek::PublicKey::from(sk);
            Jwk {
                kid: None,
                alg: Some(alg.into()),
                use_: None,
                key_ops: None,
                key: JwkParams::Okp(OkpParams {
                    crv: OkpCurve::X25519,
                    x: pk.as_bytes().to_vec(),
                    d: Some(sk.to_bytes().to_vec()),
                }),
            }
        }
        EcPrivateKey::P256(sk) => {
            let pk = sk.public_key();
            let point = pk.to_sec1_point(false);
            Jwk {
                kid: None,
                alg: Some(alg.into()),
                use_: None,
                key_ops: None,
                key: JwkParams::Ec(EcParams {
                    crv: EcCurve::P256,
                    x: point.x().unwrap().to_vec(),
                    y: point.y().unwrap().to_vec(),
                    d: Some(sk.to_bytes().to_vec()),
                }),
            }
        }
        EcPrivateKey::P384(sk) => {
            let pk = sk.public_key();
            let point = pk.to_sec1_point(false);
            Jwk {
                kid: None,
                alg: Some(alg.into()),
                use_: None,
                key_ops: None,
                key: JwkParams::Ec(EcParams {
                    crv: EcCurve::P384,
                    x: point.x().unwrap().to_vec(),
                    y: point.y().unwrap().to_vec(),
                    d: Some(sk.to_bytes().to_vec()),
                }),
            }
        }
    }
}

fn ec_pubkey_from_jwk(jwk: &Jwk, expected_alg: &str) -> JoseResult<EcPublicKey> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Ec(p) => match p.crv {
            EcCurve::P256 => {
                let mut sec1 = Vec::with_capacity(1 + p.x.len() + p.y.len());
                sec1.push(0x04);
                sec1.extend_from_slice(&p.x);
                sec1.extend_from_slice(&p.y);
                let pk = p256::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                Ok(EcPublicKey::P256(pk))
            }
            EcCurve::P384 => {
                let mut sec1 = Vec::with_capacity(1 + p.x.len() + p.y.len());
                sec1.push(0x04);
                sec1.extend_from_slice(&p.x);
                sec1.extend_from_slice(&p.y);
                let pk = p384::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                Ok(EcPublicKey::P384(pk))
            }
            _ => Err(Report::new(JoseError::InvalidKey)),
        },
        JwkParams::Okp(p) if p.crv == OkpCurve::X25519 => {
            let x: [u8; 32] =
                p.x.as_slice()
                    .try_into()
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
            Ok(EcPublicKey::X25519(x25519_dalek::PublicKey::from(x)))
        }
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

fn ec_privkey_from_jwk(jwk: &Jwk, expected_alg: &str) -> JoseResult<EcPrivateKey> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Ec(p) => {
            let d = p.d.as_ref().ok_or(Report::new(JoseError::InvalidKey))?;
            match p.crv {
                EcCurve::P256 => {
                    let sk = p256::SecretKey::from_slice(d)
                        .map_err(|_| Report::new(JoseError::InvalidKey))?;
                    Ok(EcPrivateKey::P256(sk))
                }
                EcCurve::P384 => {
                    let sk = p384::SecretKey::from_slice(d)
                        .map_err(|_| Report::new(JoseError::InvalidKey))?;
                    Ok(EcPrivateKey::P384(sk))
                }
                _ => Err(Report::new(JoseError::InvalidKey)),
            }
        }
        JwkParams::Okp(p) if p.crv == OkpCurve::X25519 => {
            let d = p.d.as_ref().ok_or(Report::new(JoseError::InvalidKey))?;
            let d_arr: [u8; 32] = d
                .as_slice()
                .try_into()
                .map_err(|_| Report::new(JoseError::InvalidKey))?;
            Ok(EcPrivateKey::X25519(x25519_dalek::StaticSecret::from(
                d_arr,
            )))
        }
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

macro_rules! ecdh_es_jwk_impls {
    ($name:ty, $alg:literal) => {
        impl JwkKeyConvert<Encrypting> for $name {
            fn key_to_jwk(key: &EcPublicKey) -> Jwk {
                ec_pubkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<EcPublicKey> {
                ec_pubkey_from_jwk(jwk, $alg)
            }
        }
        impl JwkKeyConvert<Decrypting> for $name {
            fn key_to_jwk(key: &EcPrivateKey) -> Jwk {
                ec_privkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<EcPrivateKey> {
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

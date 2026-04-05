//! AES Key Wrap algorithms for JWE: [`A128Kw`], [`A192Kw`], [`A256Kw`].
//!
//! With key wrapping, a Key Encryption Key (KEK) wraps a randomly generated
//! Content Encryption Key (CEK) that is transmitted inside the JWE token.
//! Key constructors enforce exact KEK lengths (16 / 24 / 32 bytes).
//!
//! Use the [`a128kw`], [`a192kw`], or [`a256kw`] submodules to create
//! encryption and decryption keys.

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use aes_kw::KeyInit;
use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::__private::Sealed;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{
    JweKeyManagement, KeyDecryptor, KeyEncryptionResult, KeyEncryptor,
};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OctParams};
use no_way_jose_core::key::{Decrypting, Encrypting, HasKey};

fn make_kek(bytes: impl Into<Vec<u8>>, expected_len: usize) -> JoseResult<Vec<u8>> {
    let raw = bytes.into();
    if raw.len() != expected_len {
        return Err(Report::new(JoseError::InvalidKey));
    }
    Ok(raw)
}

macro_rules! aes_kw_algorithm {
    ($name:ident, $alg:literal, $kek_len:literal, $kek_type:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl Sealed for $name {}

        impl JweKeyManagement for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Encrypting> for $name {
            type Key = Vec<u8>;
        }

        impl HasKey<Decrypting> for $name {
            type Key = Vec<u8>;
        }

        impl KeyEncryptor for $name {
            fn encrypt_cek(key: &Vec<u8>, cek_len: usize) -> JoseResult<KeyEncryptionResult> {
                let kek = <$kek_type>::new_from_slice(key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;

                let mut cek = vec![0u8; cek_len];
                getrandom::fill(&mut cek).map_err(|_| Report::new(JoseError::CryptoError))?;

                let mut wrapped = vec![0u8; cek_len + aes_kw::IV_LEN];
                kek.wrap_key(&cek, &mut wrapped)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(KeyEncryptionResult {
                    encrypted_key: wrapped,
                    cek,
                    extra_headers: Vec::new(),
                })
            }
        }

        impl KeyDecryptor for $name {
            fn decrypt_cek(
                key: &Vec<u8>,
                encrypted_key: &[u8],
                _header: &[u8],
                _cek_len: usize,
            ) -> JoseResult<Vec<u8>> {
                let kek = <$kek_type>::new_from_slice(key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;

                if encrypted_key.len() < aes_kw::IV_LEN {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                let mut buf = vec![0u8; encrypted_key.len() - aes_kw::IV_LEN];
                kek.unwrap_key(encrypted_key, &mut buf)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(buf)
            }
        }
    };
}

aes_kw_algorithm!(
    A128Kw,
    "A128KW",
    16,
    aes_kw::KwAes128,
    "AES-128 Key Wrap (RFC 7518 \u{a7}4.4)."
);

aes_kw_algorithm!(
    A192Kw,
    "A192KW",
    24,
    aes_kw::KwAes192,
    "AES-192 Key Wrap (RFC 7518 \u{a7}4.4)."
);

aes_kw_algorithm!(
    A256Kw,
    "A256KW",
    32,
    aes_kw::KwAes256,
    "AES-256 Key Wrap (RFC 7518 \u{a7}4.4)."
);

fn oct_to_jwk(key_bytes: &[u8], alg: &str) -> Jwk {
    Jwk {
        kty: "oct".into(),
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        params: JwkParams::Oct(OctParams {
            k: key_bytes.to_vec(),
        }),
    }
}

fn oct_from_jwk(jwk: &Jwk, expected_alg: &str, expected_len: usize) -> JoseResult<Vec<u8>> {
    if jwk.kty != "oct" {
        return Err(Report::new(JoseError::InvalidKey));
    }
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.params {
        JwkParams::Oct(p) => make_kek(p.k.clone(), expected_len),
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

macro_rules! aes_kw_jwk_impls {
    ($name:ident, $alg:literal, $kek_len:literal) => {
        impl JwkKeyConvert<Encrypting> for $name {
            fn key_to_jwk(key: &Vec<u8>) -> Jwk {
                oct_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<Vec<u8>> {
                oct_from_jwk(jwk, $alg, $kek_len)
            }
        }
        impl JwkKeyConvert<Decrypting> for $name {
            fn key_to_jwk(key: &Vec<u8>) -> Jwk {
                oct_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<Vec<u8>> {
                oct_from_jwk(jwk, $alg, $kek_len)
            }
        }
    };
}

aes_kw_jwk_impls!(A128Kw, "A128KW", 16);
aes_kw_jwk_impls!(A192Kw, "A192KW", 24);
aes_kw_jwk_impls!(A256Kw, "A256KW", 32);

pub mod a128kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::A128Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::A128Kw>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 16 bytes.
    pub fn encryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> no_way_jose_core::error::JoseResult<EncryptionKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 16)?))
    }

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 16 bytes.
    pub fn decryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> no_way_jose_core::error::JoseResult<DecryptionKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 16)?))
    }
}

pub mod a192kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::A192Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::A192Kw>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 24 bytes.
    pub fn encryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> no_way_jose_core::error::JoseResult<EncryptionKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 24)?))
    }

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 24 bytes.
    pub fn decryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> no_way_jose_core::error::JoseResult<DecryptionKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 24)?))
    }
}

pub mod a256kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::A256Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::A256Kw>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 32 bytes.
    pub fn encryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> no_way_jose_core::error::JoseResult<EncryptionKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 32)?))
    }

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 32 bytes.
    pub fn decryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> no_way_jose_core::error::JoseResult<DecryptionKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 32)?))
    }
}

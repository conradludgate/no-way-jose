//! PBES2 password-based encryption algorithms for JWE (RFC 7518 §4.8):
//! [`Pbes2Hs256A128Kw`], [`Pbes2Hs384A192Kw`], [`Pbes2Hs512A256Kw`].
//!
//! Derives a key from a password using PBKDF2-HMAC, then wraps a random CEK
//! with AES Key Wrap. The salt (`p2s`) and iteration count (`p2c`) are stored
//! in the JWE protected header.

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use aes_kw::KeyInit;
use base64ct::{Base64UrlUnpadded, Encoding};
use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{
    JweKeyManagement, KeyDecryptor, KeyEncryptionResult, KeyEncryptor,
};
use no_way_jose_core::key::{Decrypting, Encrypting, HasKey};

const DEFAULT_ITER_COUNT: u32 = 310_000;
const SALT_LEN: usize = 16;

/// Build the PBES2 salt value: UTF8(alg) || 0x00 || `random_salt` (RFC 7518 §4.8.1.1).
fn pbes2_salt_input(alg: &str, random_salt: &[u8]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(alg.len() + 1 + random_salt.len());
    salt.extend_from_slice(alg.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(random_salt);
    salt
}

macro_rules! pbes2_algorithm {
    ($name:ident, $alg:literal, $dk_len:literal, $hmac:ty, $kek_type:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

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
            fn encrypt_cek(password: &Vec<u8>, cek_len: usize) -> JoseResult<KeyEncryptionResult> {
                let mut random_salt = [0u8; SALT_LEN];
                getrandom::fill(&mut random_salt)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let salt_input = pbes2_salt_input($alg, &random_salt);

                let mut derived_key = [0u8; $dk_len];
                pbkdf2::pbkdf2::<$hmac>(
                    password,
                    &salt_input,
                    DEFAULT_ITER_COUNT,
                    &mut derived_key,
                )
                .map_err(|_| Report::new(JoseError::CryptoError))?;

                let kek = <$kek_type>::new_from_slice(&derived_key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;

                let mut cek = vec![0u8; cek_len];
                getrandom::fill(&mut cek).map_err(|_| Report::new(JoseError::CryptoError))?;

                let mut wrapped = vec![0u8; cek_len + aes_kw::IV_LEN];
                kek.wrap_key(&cek, &mut wrapped)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let p2s_b64 = Base64UrlUnpadded::encode_string(&random_salt);
                let p2s_json = alloc::format!("\"{p2s_b64}\"");

                let p2c_json = alloc::format!("{DEFAULT_ITER_COUNT}");

                let extra_headers = alloc::vec![
                    (String::from("p2s"), p2s_json),
                    (String::from("p2c"), p2c_json),
                ];

                Ok(KeyEncryptionResult {
                    encrypted_key: wrapped,
                    cek,
                    extra_headers,
                })
            }
        }

        impl KeyDecryptor for $name {
            fn decrypt_cek(
                password: &Vec<u8>,
                encrypted_key: &[u8],
                header: &[u8],
                _cek_len: usize,
            ) -> JoseResult<Vec<u8>> {
                let p2s_b64 = no_way_jose_core::json::read_header_string(header, "p2s")?;
                let random_salt = Base64UrlUnpadded::decode_vec(&p2s_b64)
                    .map_err(|_| Report::new(JoseError::Base64Decode))?;
                let p2c = no_way_jose_core::json::read_header_i64(header, "p2c")?;
                if p2c <= 0 {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                let p2c_u32 =
                    u32::try_from(p2c).map_err(|_| Report::new(JoseError::MalformedToken))?;

                let salt_input = pbes2_salt_input($alg, &random_salt);

                let mut derived_key = [0u8; $dk_len];
                pbkdf2::pbkdf2::<$hmac>(password, &salt_input, p2c_u32, &mut derived_key)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let kek = <$kek_type>::new_from_slice(&derived_key)
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

pbes2_algorithm!(
    Pbes2Hs256A128Kw,
    "PBES2-HS256+A128KW",
    16,
    hmac::Hmac<sha2::Sha256>,
    aes_kw::KwAes128,
    "PBES2-HS256+A128KW password-based encryption (RFC 7518 §4.8)."
);

pbes2_algorithm!(
    Pbes2Hs384A192Kw,
    "PBES2-HS384+A192KW",
    24,
    hmac::Hmac<sha2::Sha384>,
    aes_kw::KwAes192,
    "PBES2-HS384+A192KW password-based encryption (RFC 7518 §4.8)."
);

pbes2_algorithm!(
    Pbes2Hs512A256Kw,
    "PBES2-HS512+A256KW",
    32,
    hmac::Hmac<sha2::Sha512>,
    aes_kw::KwAes256,
    "PBES2-HS512+A256KW password-based encryption (RFC 7518 §4.8)."
);

pub mod pbes2_hs256_a128kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::Pbes2Hs256A128Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::Pbes2Hs256A128Kw>;

    pub fn encryption_key(password: impl Into<Vec<u8>>) -> EncryptionKey {
        no_way_jose_core::key::Key::new(password.into())
    }

    pub fn decryption_key(password: impl Into<Vec<u8>>) -> DecryptionKey {
        no_way_jose_core::key::Key::new(password.into())
    }
}

pub mod pbes2_hs384_a192kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::Pbes2Hs384A192Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::Pbes2Hs384A192Kw>;

    pub fn encryption_key(password: impl Into<Vec<u8>>) -> EncryptionKey {
        no_way_jose_core::key::Key::new(password.into())
    }

    pub fn decryption_key(password: impl Into<Vec<u8>>) -> DecryptionKey {
        no_way_jose_core::key::Key::new(password.into())
    }
}

pub mod pbes2_hs512_a256kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::Pbes2Hs512A256Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::Pbes2Hs512A256Kw>;

    pub fn encryption_key(password: impl Into<Vec<u8>>) -> EncryptionKey {
        no_way_jose_core::key::Key::new(password.into())
    }

    pub fn decryption_key(password: impl Into<Vec<u8>>) -> DecryptionKey {
        no_way_jose_core::key::Key::new(password.into())
    }
}

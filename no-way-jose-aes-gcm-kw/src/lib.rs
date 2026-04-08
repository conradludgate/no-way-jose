//! AES-GCM key wrapping for JWE: [`A128GcmKw`], [`A192GcmKw`], [`A256GcmKw`].
//!
//! | Algorithm | KEK size | Header params | RFC |
//! |-----------|----------|---------------|-----|
//! | A128GCMKW | 16 bytes | `iv`, `tag` (base64url JSON strings) | [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518#section-4.7) |
//! | A192GCMKW | 24 bytes | same | [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518#section-4.7) |
//! | A256GCMKW | 32 bytes | same | [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518#section-4.7) |
//!
//! The KEK encrypts a random CEK with AES-GCM; wrapping `iv` and `tag` are placed in the protected
//! header. Combine with a content algorithm such as [`A128Gcm`](no_way_jose_aes_gcm::A128Gcm) on
//! [`CompactJwe`](no_way_jose_core::CompactJwe).
//!
//! ```
//! use no_way_jose_aes_gcm::A128Gcm;
//! use no_way_jose_aes_gcm_kw::a128gcmkw;
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::purpose::Encrypted;
//! use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
//! use no_way_jose_core::validation::NoValidation;
//!
//! let kek = vec![0x42u8; 16];
//! let enc_key = a128gcmkw::key(kek.clone()).unwrap();
//! let dec_key = a128gcmkw::key(kek).unwrap();
//!
//! let token =
//!     UnsealedToken::<Encrypted<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm>, RawJson>::new(
//!         RawJson(r#"{"sub":"demo"}"#.into()),
//!     );
//! let compact = token.encrypt(&enc_key).unwrap();
//! let parsed: CompactJwe<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm, RawJson> =
//!     compact.to_string().parse().unwrap();
//! let unsealed = parsed
//!     .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
//! ```
//!
//! See [no-way-jose-core](https://docs.rs/no-way-jose-core) and
//! [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U12;
use aes_gcm::{AesGcm, KeyInit, Nonce};
use base64ct::{Base64UrlUnpadded, Encoding};
pub use no_way_jose_core;

type Aes192Gcm = AesGcm<aes::Aes192, U12>;

use error_stack::Report;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{JweKeyManagement, KeyEncryptionResult, KeyManager};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OctParams};
use no_way_jose_core::key::{Encrypting, HasKey};

fn make_kek(bytes: impl Into<Vec<u8>>, expected_len: usize) -> JoseResult<Vec<u8>> {
    let raw = bytes.into();
    if raw.len() != expected_len {
        return Err(Report::new(JoseError::InvalidKey));
    }
    Ok(raw)
}

fn b64_json_string(data: &[u8]) -> String {
    let encoded = Base64UrlUnpadded::encode_string(data);
    alloc::format!("\"{encoded}\"")
}

macro_rules! aes_gcm_kw_algorithm {
    ($name:ident, $alg:literal, $kek_len:literal, $cipher:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl JweKeyManagement for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Encrypting> for $name {
            type Key = Vec<u8>;
        }

        impl KeyManager for $name {
            fn encrypt_cek(key: &Vec<u8>, cek_len: usize) -> JoseResult<KeyEncryptionResult> {
                let cipher = <$cipher>::new_from_slice(key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;

                let mut iv_bytes = [0u8; 12];
                getrandom::fill(&mut iv_bytes).map_err(|_| Report::new(JoseError::CryptoError))?;
                let nonce = Nonce::from(iv_bytes);

                let mut cek = vec![0u8; cek_len];
                getrandom::fill(&mut cek).map_err(|_| Report::new(JoseError::CryptoError))?;

                let payload = aes_gcm::aead::Payload {
                    msg: &cek,
                    aad: &[],
                };
                let ciphertext_with_tag = cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let tag_start = ciphertext_with_tag.len() - 16;
                let encrypted_key = ciphertext_with_tag[..tag_start].to_vec();
                let tag = &ciphertext_with_tag[tag_start..];

                let extra_headers = alloc::vec![
                    (String::from("iv"), b64_json_string(&iv_bytes)),
                    (String::from("tag"), b64_json_string(tag)),
                ];

                Ok(KeyEncryptionResult {
                    encrypted_key,
                    cek,
                    extra_headers,
                })
            }

            fn decrypt_cek(
                key: &Vec<u8>,
                encrypted_key: &[u8],
                header: &[u8],
                _cek_len: usize,
            ) -> JoseResult<Vec<u8>> {
                let cipher = <$cipher>::new_from_slice(key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;

                let iv_bytes = no_way_jose_core::json::read_header_b64(header, "iv")?;
                let tag_bytes = no_way_jose_core::json::read_header_b64(header, "tag")?;

                if iv_bytes.len() != 12 {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                if tag_bytes.len() != 16 {
                    return Err(Report::new(JoseError::MalformedToken));
                }

                #[allow(deprecated)]
                let nonce = Nonce::from_slice(&iv_bytes);

                let mut ct_with_tag = Vec::with_capacity(encrypted_key.len() + tag_bytes.len());
                ct_with_tag.extend_from_slice(encrypted_key);
                ct_with_tag.extend_from_slice(&tag_bytes);

                let payload = aes_gcm::aead::Payload {
                    msg: &ct_with_tag,
                    aad: &[],
                };
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

aes_gcm_kw_algorithm!(
    A128GcmKw,
    "A128GCMKW",
    16,
    aes_gcm::Aes128Gcm,
    "AES-128-GCM key wrapping (RFC 7518 §4.7)."
);

aes_gcm_kw_algorithm!(
    A192GcmKw,
    "A192GCMKW",
    24,
    Aes192Gcm,
    "AES-192-GCM key wrapping (RFC 7518 §4.7)."
);

aes_gcm_kw_algorithm!(
    A256GcmKw,
    "A256GCMKW",
    32,
    aes_gcm::Aes256Gcm,
    "AES-256-GCM key wrapping (RFC 7518 §4.7)."
);

fn oct_to_jwk(key_bytes: &[u8], alg: &str) -> Jwk {
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Oct(OctParams {
            k: key_bytes.to_vec(),
        }),
    }
}

fn oct_from_jwk(jwk: &Jwk, expected_alg: &str, expected_len: usize) -> JoseResult<Vec<u8>> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Oct(p) => make_kek(p.k.clone(), expected_len),
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

macro_rules! aes_gcm_kw_jwk_impls {
    ($name:ident, $alg:literal, $kek_len:literal) => {
        impl JwkKeyConvert<Encrypting> for $name {
            fn key_to_jwk(key: &Vec<u8>) -> Jwk {
                oct_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<Vec<u8>> {
                oct_from_jwk(jwk, $alg, $kek_len)
            }
        }
    };
}

aes_gcm_kw_jwk_impls!(A128GcmKw, "A128GCMKW", 16);
aes_gcm_kw_jwk_impls!(A192GcmKw, "A192GCMKW", 24);
aes_gcm_kw_jwk_impls!(A256GcmKw, "A256GCMKW", 32);

pub mod a128gcmkw {
    use alloc::vec::Vec;

    pub type Key = no_way_jose_core::EncryptionKey<super::A128GcmKw>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 16 bytes.
    pub fn key(bytes: impl Into<Vec<u8>>) -> no_way_jose_core::error::JoseResult<Key> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 16)?))
    }
}

pub mod a192gcmkw {
    use alloc::vec::Vec;

    pub type Key = no_way_jose_core::EncryptionKey<super::A192GcmKw>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 24 bytes.
    pub fn key(bytes: impl Into<Vec<u8>>) -> no_way_jose_core::error::JoseResult<Key> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 24)?))
    }
}

pub mod a256gcmkw {
    use alloc::vec::Vec;

    pub type Key = no_way_jose_core::EncryptionKey<super::A256GcmKw>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the KEK length is not 32 bytes.
    pub fn key(bytes: impl Into<Vec<u8>>) -> no_way_jose_core::error::JoseResult<Key> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 32)?))
    }
}

//! AES-GCM content encryption for JWE ([`A128Gcm`], [`A192Gcm`], [`A256Gcm`]).
//!
//! | Algorithm | CEK size | IV | Tag | RFC |
//! |-----------|----------|----|-----|-----|
//! | A128GCM | 16 bytes | 12 bytes | 16 bytes | [RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3) |
//! | A192GCM | 24 bytes | 12 bytes | 16 bytes | [RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3) |
//! | A256GCM | 32 bytes | 12 bytes | 16 bytes | [RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3) |
//!
//! These types implement [`ContentCipher`](no_way_jose_core::jwe_algorithm::ContentCipher) from
//! [no-way-jose-core](https://docs.rs/no-way-jose-core). Use them as the `CE` type parameter on
//! [`CompactJwe`](no_way_jose_core::CompactJwe) together with a key-management algorithm (`dir`,
//! AES-KW, ECDH-ES, etc.).
//!
//! ```
//! use no_way_jose_aes_gcm::A256Gcm;
//! use no_way_jose_core::dir;
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::purpose::Encrypted;
//! use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
//! use no_way_jose_core::validation::NoValidation;
//!
//! let cek = vec![0u8; 32];
//! let enc_key = dir::key(cek.clone());
//! let dec_key = dir::key(cek);
//!
//! let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, RawJson>::new(RawJson(
//!     r#"{"sub":"demo"}"#.into(),
//! ));
//! let compact = token.encrypt(&enc_key).unwrap();
//! let parsed: CompactJwe<dir::Dir, A256Gcm, RawJson> = compact.to_string().parse().unwrap();
//! let unsealed = parsed
//!     .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
//! ```
//!
//! See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and
//! [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::vec::Vec;

use aes_gcm::aead::Aead;
use aes_gcm::{KeyInit, Nonce};
use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{ContentCipher, EncryptionOutput, JweContentEncryption};

macro_rules! aes_gcm_algorithm {
    ($name:ident, $enc:literal, $key_len:literal, $cipher:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl JweContentEncryption for $name {
            const ENC: &'static str = $enc;
            const KEY_LEN: usize = $key_len;
            const IV_LEN: usize = 12;
            const TAG_LEN: usize = 16;
        }

        impl ContentCipher for $name {
            fn encrypt(cek: &[u8], aad: &[u8], plaintext: &[u8]) -> JoseResult<EncryptionOutput> {
                let cipher = <$cipher>::new_from_slice(cek)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;

                let mut iv = [0u8; 12];
                getrandom::fill(&mut iv).map_err(|_| Report::new(JoseError::CryptoError))?;
                let nonce = Nonce::from(iv);

                let payload = aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                };
                let ciphertext_with_tag = cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let tag_start = ciphertext_with_tag.len() - 16;
                let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
                let tag = ciphertext_with_tag[tag_start..].to_vec();

                Ok(EncryptionOutput {
                    iv: nonce.to_vec(),
                    ciphertext,
                    tag,
                })
            }

            fn decrypt(
                cek: &[u8],
                iv: &[u8],
                aad: &[u8],
                ciphertext: &[u8],
                tag: &[u8],
            ) -> JoseResult<Vec<u8>> {
                let cipher = <$cipher>::new_from_slice(cek)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                if iv.len() != 12 {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                #[allow(deprecated)]
                let nonce = Nonce::from_slice(iv);

                let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
                ct_with_tag.extend_from_slice(ciphertext);
                ct_with_tag.extend_from_slice(tag);

                let payload = aes_gcm::aead::Payload {
                    msg: &ct_with_tag,
                    aad,
                };
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

aes_gcm_algorithm!(
    A128Gcm,
    "A128GCM",
    16,
    aes_gcm::Aes128Gcm,
    "AES-128-GCM content encryption (RFC 7518 \u{a7}5.3)."
);

type Aes192Gcm_ = aes_gcm::AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;

aes_gcm_algorithm!(
    A192Gcm,
    "A192GCM",
    24,
    Aes192Gcm_,
    "AES-192-GCM content encryption (RFC 7518 \u{a7}5.3)."
);

aes_gcm_algorithm!(
    A256Gcm,
    "A256GCM",
    32,
    aes_gcm::Aes256Gcm,
    "AES-256-GCM content encryption (RFC 7518 \u{a7}5.3)."
);

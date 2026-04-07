//! AES-CBC + HMAC-SHA content encryption algorithms for JWE (RFC 7518 §5.2):
//! [`A128CbcHs256`], [`A192CbcHs384`], [`A256CbcHs512`].
//!
//! These implement `ContentCipher` from `no-way-jose-core`.
//! The combined key is split: first half for HMAC, second half for AES-CBC.

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::vec::Vec;

use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use error_stack::Report;
use hmac::{KeyInit, Mac};
pub use no_way_jose_core;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{ContentCipher, EncryptionOutput, JweContentEncryption};

const IV_LEN: usize = 16;

/// RFC 7518 §5.2.2.1: HMAC input is AAD || IV || ciphertext || AL,
/// where AL is the AAD length in bits as a big-endian u64.
fn hmac_input(aad: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let al = (aad.len() as u64) * 8;
    let mut input = Vec::with_capacity(aad.len() + iv.len() + ciphertext.len() + 8);
    input.extend_from_slice(aad);
    input.extend_from_slice(iv);
    input.extend_from_slice(ciphertext);
    input.extend_from_slice(&al.to_be_bytes());
    input
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

macro_rules! aes_cbc_hs_algorithm {
    ($name:ident, $enc:literal, $key_len:literal, $mac_key_len:literal, $enc_key_len:literal, $tag_len:literal, $aes:ty, $hmac:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl JweContentEncryption for $name {
            const ENC: &'static str = $enc;
            const KEY_LEN: usize = $key_len;
            const IV_LEN: usize = IV_LEN;
            const TAG_LEN: usize = $tag_len;
        }

        impl ContentCipher for $name {
            fn encrypt(cek: &[u8], aad: &[u8], plaintext: &[u8]) -> JoseResult<EncryptionOutput> {
                if cek.len() != $key_len {
                    return Err(Report::new(JoseError::InvalidKey));
                }
                let mac_key = &cek[..$mac_key_len];
                let enc_key = &cek[$mac_key_len..];

                let mut iv = [0u8; IV_LEN];
                getrandom::fill(&mut iv).map_err(|_| Report::new(JoseError::CryptoError))?;

                let ciphertext = cbc::Encryptor::<$aes>::new_from_slices(enc_key, &iv)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?
                    .encrypt_padded_vec::<Pkcs7>(plaintext);

                let hmac_data = hmac_input(aad, &iv, &ciphertext);
                let mut mac = <$hmac>::new_from_slice(mac_key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                mac.update(&hmac_data);
                let tag = mac.finalize().into_bytes()[..$tag_len].to_vec();

                Ok(EncryptionOutput {
                    iv: iv.to_vec(),
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
                if cek.len() != $key_len {
                    return Err(Report::new(JoseError::InvalidKey));
                }
                if iv.len() != IV_LEN {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                if tag.len() != $tag_len {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                let mac_key = &cek[..$mac_key_len];
                let enc_key = &cek[$mac_key_len..];

                let hmac_data = hmac_input(aad, iv, ciphertext);
                let mut mac = <$hmac>::new_from_slice(mac_key)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                mac.update(&hmac_data);
                let expected_tag = &mac.finalize().into_bytes()[..$tag_len];
                if !constant_time_eq(tag, expected_tag) {
                    return Err(Report::new(JoseError::CryptoError));
                }

                cbc::Decryptor::<$aes>::new_from_slices(enc_key, iv)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

aes_cbc_hs_algorithm!(
    A128CbcHs256,
    "A128CBC-HS256",
    32,
    16,
    16,
    16,
    aes::Aes128,
    hmac::Hmac<sha2::Sha256>,
    "AES-128-CBC + HMAC-SHA-256 content encryption (RFC 7518 §5.2)."
);

aes_cbc_hs_algorithm!(
    A192CbcHs384,
    "A192CBC-HS384",
    48,
    24,
    24,
    24,
    aes::Aes192,
    hmac::Hmac<sha2::Sha384>,
    "AES-192-CBC + HMAC-SHA-384 content encryption (RFC 7518 §5.2)."
);

aes_cbc_hs_algorithm!(
    A256CbcHs512,
    "A256CBC-HS512",
    64,
    32,
    32,
    32,
    aes::Aes256,
    hmac::Hmac<sha2::Sha512>,
    "AES-256-CBC + HMAC-SHA-512 content encryption (RFC 7518 §5.2)."
);

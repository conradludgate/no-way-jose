//! AES-CBC + HMAC-SHA content encryption algorithms for JWE (RFC 7518 §5.2):
//! [`A128CbcHs256`], [`A192CbcHs384`], [`A256CbcHs512`].
//!
//! These implement `ContentEncryptor` / `ContentDecryptor` from `no-way-jose-core`.
//! The combined key is split: first half for HMAC, second half for AES-CBC.

#![no_std]

extern crate alloc;

pub use no_way_jose_core;

use alloc::vec::Vec;

use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{KeyInit, Mac};

use no_way_jose_core::__private::Sealed;
use no_way_jose_core::JoseError;
use no_way_jose_core::jwe_algorithm::{
    ContentDecryptor, ContentEncryptor, EncryptionOutput, JweContentEncryption,
};

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
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

macro_rules! aes_cbc_hs_algorithm {
    ($name:ident, $enc:literal, $key_len:literal, $mac_key_len:literal, $enc_key_len:literal, $tag_len:literal, $aes:ty, $hmac:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl Sealed for $name {}

        impl JweContentEncryption for $name {
            const ENC: &'static str = $enc;
            const KEY_LEN: usize = $key_len;
            const IV_LEN: usize = IV_LEN;
            const TAG_LEN: usize = $tag_len;
        }

        impl ContentEncryptor for $name {
            fn encrypt(
                cek: &[u8],
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<EncryptionOutput, JoseError> {
                if cek.len() != $key_len {
                    return Err(JoseError::InvalidKey);
                }
                let mac_key = &cek[..$mac_key_len];
                let enc_key = &cek[$mac_key_len..];

                let mut iv = [0u8; IV_LEN];
                getrandom::fill(&mut iv).map_err(|_| JoseError::CryptoError)?;

                let ciphertext = cbc::Encryptor::<$aes>::new_from_slices(enc_key, &iv)
                    .map_err(|_| JoseError::InvalidKey)?
                    .encrypt_padded_vec::<Pkcs7>(plaintext);

                let hmac_data = hmac_input(aad, &iv, &ciphertext);
                let mut mac =
                    <$hmac>::new_from_slice(mac_key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(&hmac_data);
                let tag = mac.finalize().into_bytes()[..$tag_len].to_vec();

                Ok(EncryptionOutput {
                    iv: iv.to_vec(),
                    ciphertext,
                    tag,
                })
            }
        }

        impl ContentDecryptor for $name {
            fn decrypt(
                cek: &[u8],
                iv: &[u8],
                aad: &[u8],
                ciphertext: &[u8],
                tag: &[u8],
            ) -> Result<Vec<u8>, JoseError> {
                if cek.len() != $key_len {
                    return Err(JoseError::InvalidKey);
                }
                if iv.len() != IV_LEN {
                    return Err(JoseError::InvalidToken("invalid IV length"));
                }
                if tag.len() != $tag_len {
                    return Err(JoseError::InvalidToken("invalid tag length"));
                }
                let mac_key = &cek[..$mac_key_len];
                let enc_key = &cek[$mac_key_len..];

                // Authenticate before decrypting
                let hmac_data = hmac_input(aad, iv, ciphertext);
                let mut mac =
                    <$hmac>::new_from_slice(mac_key).map_err(|_| JoseError::InvalidKey)?;
                mac.update(&hmac_data);
                let expected_tag = &mac.finalize().into_bytes()[..$tag_len];
                if !constant_time_eq(tag, expected_tag) {
                    return Err(JoseError::CryptoError);
                }

                cbc::Decryptor::<$aes>::new_from_slices(enc_key, iv)
                    .map_err(|_| JoseError::InvalidKey)?
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
                    .map_err(|_| JoseError::CryptoError)
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

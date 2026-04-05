#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use aes_gcm::aead::Aead;
use aes_gcm::{KeyInit, Nonce};

use no_way_jose_core::__private::Sealed;
use no_way_jose_core::JoseError;
use no_way_jose_core::jwe_algorithm::{
    ContentDecryptor, ContentEncryptor, EncryptionOutput, JweContentEncryption,
};

macro_rules! aes_gcm_algorithm {
    ($name:ident, $enc:literal, $key_len:literal, $cipher:ty, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl Sealed for $name {}

        impl JweContentEncryption for $name {
            const ENC: &'static str = $enc;
            const KEY_LEN: usize = $key_len;
            const IV_LEN: usize = 12;
            const TAG_LEN: usize = 16;
        }

        impl ContentEncryptor for $name {
            fn encrypt(
                cek: &[u8],
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<EncryptionOutput, JoseError> {
                let cipher = <$cipher>::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;

                let mut iv = [0u8; 12];
                getrandom::fill(&mut iv).map_err(|_| JoseError::CryptoError)?;
                let nonce = Nonce::from(iv);

                let payload = aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                };
                let ciphertext_with_tag = cipher
                    .encrypt(&nonce, payload)
                    .map_err(|_| JoseError::CryptoError)?;

                let tag_start = ciphertext_with_tag.len() - 16;
                let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
                let tag = ciphertext_with_tag[tag_start..].to_vec();

                Ok(EncryptionOutput {
                    iv: nonce.to_vec(),
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
                let cipher = <$cipher>::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;
                if iv.len() != 12 {
                    return Err(JoseError::InvalidToken("invalid IV length"));
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
                    .map_err(|_| JoseError::CryptoError)
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

aes_gcm_algorithm!(
    A256Gcm,
    "A256GCM",
    32,
    aes_gcm::Aes256Gcm,
    "AES-256-GCM content encryption (RFC 7518 \u{a7}5.3)."
);

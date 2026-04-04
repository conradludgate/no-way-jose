#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use jose_core::__private::Sealed;
use jose_core::JoseError;
use jose_core::jwe_algorithm::{
    ContentDecryptor, ContentEncryptor, EncryptionOutput, JweContentEncryption,
};

/// AES-256-GCM content encryption algorithm (RFC 7518 §5.3).
#[derive(Clone, Copy, Debug, Default)]
pub struct A256Gcm;

impl Sealed for A256Gcm {}

impl JweContentEncryption for A256Gcm {
    const ENC: &'static str = "A256GCM";
    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 12;
    const TAG_LEN: usize = 16;
}

impl ContentEncryptor for A256Gcm {
    fn encrypt(cek: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<EncryptionOutput, JoseError> {
        let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;

        let mut iv = [0u8; Self::IV_LEN];
        getrandom::fill(&mut iv).map_err(|_| JoseError::CryptoError)?;
        let nonce = Nonce::from(iv);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext_with_tag = cipher
            .encrypt(&nonce, payload)
            .map_err(|_| JoseError::CryptoError)?;

        let tag_start = ciphertext_with_tag.len() - Self::TAG_LEN;
        let ciphertext = ciphertext_with_tag[..tag_start].to_vec();
        let tag = ciphertext_with_tag[tag_start..].to_vec();

        Ok(EncryptionOutput {
            iv: nonce.to_vec(),
            ciphertext,
            tag,
        })
    }
}

impl ContentDecryptor for A256Gcm {
    fn decrypt(
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JoseError> {
        let cipher = Aes256Gcm::new_from_slice(cek).map_err(|_| JoseError::InvalidKey)?;
        if iv.len() != Self::IV_LEN {
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

use aws_lc_rs::{aead, rand};
use error_stack::Report;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{ContentCipher, EncryptionOutput, JweContentEncryption};

macro_rules! aes_gcm_algorithm {
    ($name:ident, $enc:literal, $key_len:literal, $aead_alg:expr, $doc:literal) => {
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
                if cek.len() != $key_len {
                    return Err(Report::new(JoseError::InvalidKey));
                }

                let unbound = aead::UnboundKey::new($aead_alg, cek)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                let key = aead::LessSafeKey::new(unbound);

                let mut iv_bytes = [0u8; 12];
                rand::fill(&mut iv_bytes).map_err(|_| Report::new(JoseError::CryptoError))?;
                let nonce = aead::Nonce::try_assume_unique_for_key(&iv_bytes)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let mut in_out = plaintext.to_vec();
                let tag = key
                    .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut in_out)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                Ok(EncryptionOutput {
                    iv: iv_bytes.to_vec(),
                    ciphertext: in_out,
                    tag: tag.as_ref().to_vec(),
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
                if iv.len() != 12 {
                    return Err(Report::new(JoseError::MalformedToken));
                }

                let unbound = aead::UnboundKey::new($aead_alg, cek)
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                let key = aead::LessSafeKey::new(unbound);
                let nonce = aead::Nonce::try_assume_unique_for_key(iv)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                let mut in_out = Vec::with_capacity(ciphertext.len() + tag.len());
                in_out.extend_from_slice(ciphertext);
                in_out.extend_from_slice(tag);

                let plaintext = key
                    .open_in_place(nonce, aead::Aad::from(aad), &mut in_out)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                Ok(plaintext.to_vec())
            }
        }
    };
}

aes_gcm_algorithm!(
    A128Gcm,
    "A128GCM",
    16,
    &aead::AES_128_GCM,
    "AES-128-GCM content encryption (aws-lc-rs backend)."
);

aes_gcm_algorithm!(
    A256Gcm,
    "A256GCM",
    32,
    &aead::AES_256_GCM,
    "AES-256-GCM content encryption (aws-lc-rs backend)."
);

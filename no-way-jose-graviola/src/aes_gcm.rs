use error_stack::Report;
use graviola::aead::AesGcm;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwe_algorithm::{ContentCipher, EncryptionOutput, JweContentEncryption};

macro_rules! aes_gcm_algorithm {
    ($name:ident, $enc:literal, $key_len:literal, $doc:literal) => {
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

                let cipher = AesGcm::new(cek);

                let mut iv = [0u8; 12];
                graviola::random::fill(&mut iv).map_err(|_| Report::new(JoseError::CryptoError))?;

                let mut ciphertext = plaintext.to_vec();
                let mut tag = [0u8; 16];
                cipher.encrypt(&iv, aad, &mut ciphertext, &mut tag);

                Ok(EncryptionOutput {
                    iv: iv.to_vec(),
                    ciphertext,
                    tag: tag.to_vec(),
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
                let iv: [u8; 12] = {
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(iv);
                    arr
                };

                let cipher = AesGcm::new(cek);
                let mut plaintext = ciphertext.to_vec();
                cipher
                    .decrypt(&iv, aad, &mut plaintext, tag)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(plaintext)
            }
        }
    };
}

aes_gcm_algorithm!(
    A128Gcm,
    "A128GCM",
    16,
    "AES-128-GCM content encryption (graviola backend)."
);

aes_gcm_algorithm!(
    A256Gcm,
    "A256GCM",
    32,
    "AES-256-GCM content encryption (graviola backend)."
);

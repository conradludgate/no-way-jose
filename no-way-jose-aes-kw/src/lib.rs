#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use no_way_jose_core::__private::Sealed;
use no_way_jose_core::JoseError;
use no_way_jose_core::jwe_algorithm::{JweKeyManagement, KeyDecryptor, KeyEncryptor};
use no_way_jose_core::key::{Decrypting, Encrypting, HasKey};

fn make_kek(bytes: impl Into<Vec<u8>>, expected_len: usize) -> Result<Vec<u8>, JoseError> {
    let raw = bytes.into();
    if raw.len() != expected_len {
        return Err(JoseError::InvalidKey);
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
            fn encrypt_cek(key: &Vec<u8>, cek_len: usize) -> Result<(Vec<u8>, Vec<u8>), JoseError> {
                let kek =
                    <$kek_type>::try_from(key.as_slice()).map_err(|_| JoseError::InvalidKey)?;

                let mut cek = vec![0u8; cek_len];
                getrandom::fill(&mut cek).map_err(|_| JoseError::CryptoError)?;

                let wrapped = kek.wrap_vec(&cek).map_err(|_| JoseError::CryptoError)?;
                Ok((wrapped, cek))
            }
        }

        impl KeyDecryptor for $name {
            fn decrypt_cek(key: &Vec<u8>, encrypted_key: &[u8]) -> Result<Vec<u8>, JoseError> {
                let kek =
                    <$kek_type>::try_from(key.as_slice()).map_err(|_| JoseError::InvalidKey)?;

                kek.unwrap_vec(encrypted_key)
                    .map_err(|_| JoseError::CryptoError)
            }
        }
    };
}

aes_kw_algorithm!(
    A128Kw,
    "A128KW",
    16,
    aes_kw::KekAes128,
    "AES-128 Key Wrap (RFC 7518 \u{a7}4.4)."
);

aes_kw_algorithm!(
    A192Kw,
    "A192KW",
    24,
    aes_kw::KekAes192,
    "AES-192 Key Wrap (RFC 7518 \u{a7}4.4)."
);

aes_kw_algorithm!(
    A256Kw,
    "A256KW",
    32,
    aes_kw::KekAes256,
    "AES-256 Key Wrap (RFC 7518 \u{a7}4.4)."
);

pub mod a128kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::A128Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::A128Kw>;

    pub fn encryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<EncryptionKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 16)?))
    }

    pub fn decryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<DecryptionKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 16)?))
    }
}

pub mod a192kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::A192Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::A192Kw>;

    pub fn encryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<EncryptionKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 24)?))
    }

    pub fn decryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<DecryptionKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 24)?))
    }
}

pub mod a256kw {
    use alloc::vec::Vec;

    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::A256Kw>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::A256Kw>;

    pub fn encryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<EncryptionKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 32)?))
    }

    pub fn decryption_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<DecryptionKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_kek(bytes, 32)?))
    }
}

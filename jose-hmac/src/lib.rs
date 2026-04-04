pub use jose_core;

use hmac::{Hmac, Mac};
use jose_core::JoseError;
use jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use jose_core::key::{HasKey, Signing, Verifying};

/// Symmetric key for HMAC algorithms. Signing and verifying use the same key.
#[derive(Clone)]
pub struct HmacKey(Vec<u8>);

fn make_key(bytes: impl Into<Vec<u8>>, min_len: usize) -> Result<HmacKey, JoseError> {
    let bytes = bytes.into();
    if bytes.len() < min_len {
        return Err(JoseError::InvalidKey);
    }
    Ok(HmacKey(bytes))
}

macro_rules! hmac_algorithm {
    ($name:ident, $alg:literal, $hash:ty, $min_key_len:expr, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl jose_core::__private::Sealed for $name {}

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = HmacKey;
        }

        impl HasKey<Verifying> for $name {
            type Key = HmacKey;
        }

        impl Signer for $name {
            fn sign(key: &HmacKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
                let mut mac =
                    Hmac::<$hash>::new_from_slice(&key.0).map_err(|_| JoseError::InvalidKey)?;
                mac.update(signing_input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &HmacKey,
                signing_input: &[u8],
                signature: &[u8],
            ) -> Result<(), JoseError> {
                let mut mac =
                    Hmac::<$hash>::new_from_slice(&key.0).map_err(|_| JoseError::InvalidKey)?;
                mac.update(signing_input);
                mac.verify_slice(signature)
                    .map_err(|_| JoseError::CryptoError)
            }
        }
    };
}

hmac_algorithm!(
    Hs256,
    "HS256",
    sha2::Sha256,
    32,
    "HS256: HMAC using SHA-256 (RFC 7518 §3.2)."
);
hmac_algorithm!(
    Hs384,
    "HS384",
    sha2::Sha384,
    48,
    "HS384: HMAC using SHA-384 (RFC 7518 §3.2)."
);
hmac_algorithm!(
    Hs512,
    "HS512",
    sha2::Sha512,
    64,
    "HS512: HMAC using SHA-512 (RFC 7518 §3.2)."
);

pub mod hs256 {
    pub type SigningKey = jose_core::SigningKey<super::Hs256>;
    pub type VerifyingKey = jose_core::VerifyingKey<super::Hs256>;

    pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, jose_core::JoseError> {
        Ok(jose_core::key::Key::new(super::make_key(bytes, 32)?))
    }

    pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, jose_core::JoseError> {
        Ok(jose_core::key::Key::new(super::make_key(bytes, 32)?))
    }
}

pub mod hs384 {
    pub type SigningKey = jose_core::SigningKey<super::Hs384>;
    pub type VerifyingKey = jose_core::VerifyingKey<super::Hs384>;

    pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, jose_core::JoseError> {
        Ok(jose_core::key::Key::new(super::make_key(bytes, 48)?))
    }

    pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, jose_core::JoseError> {
        Ok(jose_core::key::Key::new(super::make_key(bytes, 48)?))
    }
}

pub mod hs512 {
    pub type SigningKey = jose_core::SigningKey<super::Hs512>;
    pub type VerifyingKey = jose_core::VerifyingKey<super::Hs512>;

    pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, jose_core::JoseError> {
        Ok(jose_core::key::Key::new(super::make_key(bytes, 64)?))
    }

    pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, jose_core::JoseError> {
        Ok(jose_core::key::Key::new(super::make_key(bytes, 64)?))
    }
}

// Backwards-compatible re-exports for Hs256.
pub type SigningKey = hs256::SigningKey;
pub type VerifyingKey = hs256::VerifyingKey;

pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, JoseError> {
    hs256::symmetric_key(bytes)
}

pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, JoseError> {
    hs256::verifying_key(bytes)
}

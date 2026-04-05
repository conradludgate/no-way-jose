//! HMAC-based JWS algorithms: [`Hs256`], [`Hs384`], [`Hs512`].
//!
//! HMAC is a symmetric algorithm -- the same secret key is used for both
//! signing and verification. Key constructors enforce minimum lengths
//! (32 / 48 / 64 bytes respectively, per RFC 7518 Section 3.2).
//!
//! The root-level [`symmetric_key`] and [`verifying_key`] functions are
//! convenience aliases for HS256. For other variants use the [`hs384`] or
//! [`hs512`] submodules.

#![no_std]

extern crate alloc;

pub use no_way_jose_core;

use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

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

        impl no_way_jose_core::__private::Sealed for $name {}

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
    use alloc::vec::Vec;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs256>;

    pub fn symmetric_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<SigningKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 32)?))
    }

    pub fn verifying_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<VerifyingKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 32)?))
    }
}

pub mod hs384 {
    use alloc::vec::Vec;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs384>;

    pub fn symmetric_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<SigningKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 48)?))
    }

    pub fn verifying_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<VerifyingKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 48)?))
    }
}

pub mod hs512 {
    use alloc::vec::Vec;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs512>;

    pub fn symmetric_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<SigningKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 64)?))
    }

    pub fn verifying_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<VerifyingKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 64)?))
    }
}

/// HS256 signing key (convenience alias).
pub type SigningKey = hs256::SigningKey;
/// HS256 verifying key (convenience alias).
pub type VerifyingKey = hs256::VerifyingKey;

/// Create an HS256 signing key. Requires at least 32 bytes.
pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, JoseError> {
    hs256::symmetric_key(bytes)
}

/// Create an HS256 verifying key. Requires at least 32 bytes.
pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, JoseError> {
    hs256::verifying_key(bytes)
}

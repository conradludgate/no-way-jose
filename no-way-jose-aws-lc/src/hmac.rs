use aws_lc_rs::hmac;
use error_stack::Report;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

fn make_key(
    alg: hmac::Algorithm,
    bytes: impl Into<Vec<u8>>,
    min_len: usize,
) -> JoseResult<hmac::Key> {
    let bytes = bytes.into();
    if bytes.len() < min_len {
        return Err(Report::new(JoseError::InvalidKey));
    }
    Ok(hmac::Key::new(alg, &bytes))
}

macro_rules! hmac_algorithm {
    ($name:ident, $alg:literal, $hmac_alg:expr, $min_key_len:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = hmac::Key;
        }

        impl HasKey<Verifying> for $name {
            type Key = hmac::Key;
        }

        impl Signer for $name {
            fn sign(key: &hmac::Key, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                Ok(hmac::sign(key, signing_input).as_ref().to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(key: &hmac::Key, signing_input: &[u8], signature: &[u8]) -> JoseResult<()> {
                hmac::verify(key, signing_input, signature)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

hmac_algorithm!(Hs256, "HS256", hmac::HMAC_SHA256, 32, "HS256: HMAC using SHA-256 (aws-lc-rs backend).");
hmac_algorithm!(Hs384, "HS384", hmac::HMAC_SHA384, 48, "HS384: HMAC using SHA-384 (aws-lc-rs backend).");
hmac_algorithm!(Hs512, "HS512", hmac::HMAC_SHA512, 64, "HS512: HMAC using SHA-512 (aws-lc-rs backend).");

pub mod hs256 {
    use aws_lc_rs::hmac;
    use no_way_jose_core::error::JoseResult;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs256>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key is shorter than 32 bytes.
    pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> JoseResult<SigningKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(
            hmac::HMAC_SHA256,
            bytes,
            32,
        )?))
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key is shorter than 32 bytes.
    pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> JoseResult<VerifyingKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(
            hmac::HMAC_SHA256,
            bytes,
            32,
        )?))
    }
}

pub mod hs384 {
    use aws_lc_rs::hmac;
    use no_way_jose_core::error::JoseResult;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs384>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key is shorter than 48 bytes.
    pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> JoseResult<SigningKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(
            hmac::HMAC_SHA384,
            bytes,
            48,
        )?))
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key is shorter than 48 bytes.
    pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> JoseResult<VerifyingKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(
            hmac::HMAC_SHA384,
            bytes,
            48,
        )?))
    }
}

pub mod hs512 {
    use aws_lc_rs::hmac;
    use no_way_jose_core::error::JoseResult;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs512>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key is shorter than 64 bytes.
    pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> JoseResult<SigningKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(
            hmac::HMAC_SHA512,
            bytes,
            64,
        )?))
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key is shorter than 64 bytes.
    pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> JoseResult<VerifyingKey> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(
            hmac::HMAC_SHA512,
            bytes,
            64,
        )?))
    }
}

pub type SigningKey = hs256::SigningKey;
pub type VerifyingKey = hs256::VerifyingKey;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key is shorter than 32 bytes.
pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> JoseResult<SigningKey> {
    hs256::symmetric_key(bytes)
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key is shorter than 32 bytes.
pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> JoseResult<VerifyingKey> {
    hs256::verifying_key(bytes)
}

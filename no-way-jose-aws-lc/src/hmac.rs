use aws_lc_rs::hmac;
use error_stack::Report;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OctParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

#[derive(Clone)]
pub struct HmacKey {
    raw: Vec<u8>,
    inner: hmac::Key,
}

impl HmacKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

fn make_key(
    alg: hmac::Algorithm,
    bytes: impl Into<Vec<u8>>,
    min_len: usize,
) -> JoseResult<HmacKey> {
    let raw = bytes.into();
    if raw.len() < min_len {
        return Err(Report::new(JoseError::InvalidKey));
    }
    let inner = hmac::Key::new(alg, &raw);
    Ok(HmacKey { raw, inner })
}

fn oct_to_jwk(key_bytes: &[u8], alg: &str) -> Jwk {
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Oct(OctParams {
            k: key_bytes.to_vec(),
        }),
    }
}

fn oct_from_jwk(
    jwk: &Jwk,
    expected_alg: &str,
    hmac_alg: hmac::Algorithm,
    min_len: usize,
) -> JoseResult<HmacKey> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Oct(p) => make_key(hmac_alg, p.k.clone(), min_len),
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

macro_rules! hmac_algorithm {
    ($name:ident, $alg:literal, $hmac_alg:expr, $min_key_len:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

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
            fn sign(key: &HmacKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                Ok(hmac::sign(&key.inner, signing_input).as_ref().to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(key: &HmacKey, signing_input: &[u8], signature: &[u8]) -> JoseResult<()> {
                hmac::verify(&key.inner, signing_input, signature)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }

        impl JwkKeyConvert<Signing> for $name {
            fn key_to_jwk(key: &HmacKey) -> Jwk {
                oct_to_jwk(key.as_bytes(), $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<HmacKey> {
                oct_from_jwk(jwk, $alg, $hmac_alg, $min_key_len)
            }
        }

        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &HmacKey) -> Jwk {
                oct_to_jwk(key.as_bytes(), $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<HmacKey> {
                oct_from_jwk(jwk, $alg, $hmac_alg, $min_key_len)
            }
        }
    };
}

hmac_algorithm!(
    Hs256,
    "HS256",
    hmac::HMAC_SHA256,
    32,
    "HS256: HMAC using SHA-256 (aws-lc-rs backend)."
);
hmac_algorithm!(
    Hs384,
    "HS384",
    hmac::HMAC_SHA384,
    48,
    "HS384: HMAC using SHA-384 (aws-lc-rs backend)."
);
hmac_algorithm!(
    Hs512,
    "HS512",
    hmac::HMAC_SHA512,
    64,
    "HS512: HMAC using SHA-512 (aws-lc-rs backend)."
);

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

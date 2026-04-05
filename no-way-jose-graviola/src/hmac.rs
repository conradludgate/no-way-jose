use graviola::hashing::hmac::Hmac;
use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OctParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

#[derive(Clone)]
pub struct HmacKey(Vec<u8>);

impl HmacKey {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

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
                let mut mac = Hmac::<$hash>::new(&key.0);
                mac.update(signing_input);
                Ok(mac.finish().as_ref().to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &HmacKey,
                signing_input: &[u8],
                signature: &[u8],
            ) -> Result<(), JoseError> {
                let mut mac = Hmac::<$hash>::new(&key.0);
                mac.update(signing_input);
                mac.verify(signature).map_err(|_| JoseError::CryptoError)
            }
        }

        impl JwkKeyConvert<Signing> for $name {
            fn key_to_jwk(key: &HmacKey) -> Jwk {
                oct_to_jwk(key.as_bytes(), $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<HmacKey, JoseError> {
                oct_from_jwk(jwk, $alg, $min_key_len)
            }
        }

        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &HmacKey) -> Jwk {
                oct_to_jwk(key.as_bytes(), $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<HmacKey, JoseError> {
                oct_from_jwk(jwk, $alg, $min_key_len)
            }
        }
    };
}

fn oct_to_jwk(key_bytes: &[u8], alg: &str) -> Jwk {
    Jwk {
        kty: "oct".into(),
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        params: JwkParams::Oct(OctParams {
            k: key_bytes.to_vec(),
        }),
    }
}

fn oct_from_jwk(jwk: &Jwk, expected_alg: &str, min_len: usize) -> Result<HmacKey, JoseError> {
    if jwk.kty != "oct" {
        return Err(JoseError::InvalidKey);
    }
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(JoseError::InvalidKey);
    }
    match &jwk.params {
        JwkParams::Oct(p) => make_key(p.k.clone(), min_len),
        _ => Err(JoseError::InvalidKey),
    }
}

hmac_algorithm!(
    Hs256,
    "HS256",
    graviola::hashing::Sha256,
    32,
    "HS256: HMAC using SHA-256 (graviola backend)."
);
hmac_algorithm!(
    Hs384,
    "HS384",
    graviola::hashing::Sha384,
    48,
    "HS384: HMAC using SHA-384 (graviola backend)."
);
hmac_algorithm!(
    Hs512,
    "HS512",
    graviola::hashing::Sha512,
    64,
    "HS512: HMAC using SHA-512 (graviola backend)."
);

pub mod hs256 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs256>;

    /// # Errors
    /// Returns `no_way_jose_core::JoseError::InvalidKey` if the key is shorter than 32 bytes.
    pub fn symmetric_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<SigningKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 32)?))
    }

    /// # Errors
    /// Returns `no_way_jose_core::JoseError::InvalidKey` if the key is shorter than 32 bytes.
    pub fn verifying_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<VerifyingKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 32)?))
    }
}

pub mod hs384 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs384>;

    /// # Errors
    /// Returns `no_way_jose_core::JoseError::InvalidKey` if the key is shorter than 48 bytes.
    pub fn symmetric_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<SigningKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 48)?))
    }

    /// # Errors
    /// Returns `no_way_jose_core::JoseError::InvalidKey` if the key is shorter than 48 bytes.
    pub fn verifying_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<VerifyingKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 48)?))
    }
}

pub mod hs512 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Hs512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Hs512>;

    /// # Errors
    /// Returns `no_way_jose_core::JoseError::InvalidKey` if the key is shorter than 64 bytes.
    pub fn symmetric_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<SigningKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 64)?))
    }

    /// # Errors
    /// Returns `no_way_jose_core::JoseError::InvalidKey` if the key is shorter than 64 bytes.
    pub fn verifying_key(
        bytes: impl Into<Vec<u8>>,
    ) -> Result<VerifyingKey, no_way_jose_core::JoseError> {
        Ok(no_way_jose_core::key::Key::new(super::make_key(bytes, 64)?))
    }
}

pub type SigningKey = hs256::SigningKey;
pub type VerifyingKey = hs256::VerifyingKey;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key is shorter than 32 bytes.
pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, JoseError> {
    hs256::symmetric_key(bytes)
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key is shorter than 32 bytes.
pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, JoseError> {
    hs256::verifying_key(bytes)
}

use error_stack::Report;
use graviola::signing::rsa;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

macro_rules! rsa_algorithm {
    ($name:ident, $alg:literal, $sign_fn:ident, $verify_fn:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;


        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = rsa::SigningKey;
        }

        impl HasKey<Verifying> for $name {
            type Key = rsa::VerifyingKey;
        }

        impl Signer for $name {
            fn sign(key: &rsa::SigningKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                let mut buf = vec![0u8; key.modulus_len_bytes()];
                let sig = key
                    .$sign_fn(&mut buf, signing_input)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(sig.to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &rsa::VerifyingKey,
                signing_input: &[u8],
                signature: &[u8],
            ) -> JoseResult<()> {
                key.$verify_fn(signature, signing_input)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

rsa_algorithm!(
    Rs256,
    "RS256",
    sign_pkcs1_sha256,
    verify_pkcs1_sha256,
    "RS256: RSASSA-PKCS1-v1_5 using SHA-256 (graviola backend)."
);

rsa_algorithm!(
    Ps256,
    "PS256",
    sign_pss_sha256,
    verify_pss_sha256,
    "PS256: RSASSA-PSS using SHA-256 (graviola backend)."
);

pub type SigningKey = no_way_jose_core::SigningKey<Rs256>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Rs256>;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the RSA key bytes are invalid.
pub fn signing_key_from_pkcs8_der(bytes: &[u8]) -> JoseResult<SigningKey> {
    rsa::SigningKey::from_pkcs8_der(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the RSA key bytes are invalid.
pub fn signing_key_from_pkcs1_der(bytes: &[u8]) -> JoseResult<SigningKey> {
    rsa::SigningKey::from_pkcs1_der(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the RSA key bytes are invalid.
pub fn verifying_key_from_pkcs1_der(bytes: &[u8]) -> JoseResult<VerifyingKey> {
    rsa::VerifyingKey::from_pkcs1_der(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(key.inner().public_key())
}

pub mod ps256 {
    use error_stack::Report;
    use graviola::signing::rsa;
    use no_way_jose_core::error::{JoseError, JoseResult};

    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps256>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the RSA key bytes are invalid.
    pub fn signing_key_from_pkcs8_der(bytes: &[u8]) -> JoseResult<SigningKey> {
        rsa::SigningKey::from_pkcs8_der(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the RSA key bytes are invalid.
    pub fn signing_key_from_pkcs1_der(bytes: &[u8]) -> JoseResult<SigningKey> {
        rsa::SigningKey::from_pkcs1_der(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the RSA key bytes are invalid.
    pub fn verifying_key_from_pkcs1_der(bytes: &[u8]) -> JoseResult<VerifyingKey> {
        rsa::VerifyingKey::from_pkcs1_der(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(key.inner().public_key())
    }
}

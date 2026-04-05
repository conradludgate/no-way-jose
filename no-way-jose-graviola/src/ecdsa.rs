use graviola::hashing::{Sha256, Sha384};
use graviola::signing::ecdsa;
use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

macro_rules! ecdsa_algorithm {
    ($name:ident, $alg:literal, $curve:ty, $hash:ty, $sig_len:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl no_way_jose_core::__private::Sealed for $name {}

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = ecdsa::SigningKey<$curve>;
        }

        impl HasKey<Verifying> for $name {
            type Key = ecdsa::VerifyingKey<$curve>;
        }

        impl Signer for $name {
            fn sign(
                key: &ecdsa::SigningKey<$curve>,
                signing_input: &[u8],
            ) -> Result<Vec<u8>, JoseError> {
                let mut buf = [0u8; $sig_len];
                let sig = key
                    .sign::<$hash>(&[signing_input], &mut buf)
                    .map_err(|_| JoseError::CryptoError)?;
                Ok(sig.to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &ecdsa::VerifyingKey<$curve>,
                signing_input: &[u8],
                signature: &[u8],
            ) -> Result<(), JoseError> {
                key.verify::<$hash>(&[signing_input], signature)
                    .map_err(|_| JoseError::CryptoError)
            }
        }
    };
}

ecdsa_algorithm!(
    Es256,
    "ES256",
    ecdsa::P256,
    Sha256,
    64,
    "ES256: ECDSA using P-256 and SHA-256 (graviola backend)."
);

ecdsa_algorithm!(
    Es384,
    "ES384",
    ecdsa::P384,
    Sha384,
    96,
    "ES384: ECDSA using P-384 and SHA-384 (graviola backend)."
);

pub type SigningKey = no_way_jose_core::SigningKey<Es256>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es256>;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_sec1_der(bytes: &[u8]) -> Result<SigningKey, JoseError> {
    ecdsa::SigningKey::from_sec1_der(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn verifying_key_from_x962(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
    ecdsa::VerifyingKey::from_x962_uncompressed(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

pub mod es384 {
    use super::{Es384, JoseError, ecdsa};

    pub type SigningKey = no_way_jose_core::SigningKey<Es384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es384>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn signing_key_from_sec1_der(bytes: &[u8]) -> Result<SigningKey, JoseError> {
        ecdsa::SigningKey::from_sec1_der(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| JoseError::InvalidKey)
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn verifying_key_from_x962(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
        ecdsa::VerifyingKey::from_x962_uncompressed(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| JoseError::InvalidKey)
    }
}

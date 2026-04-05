//! ECDSA-based JWS algorithms: [`Es256`] (P-256) and [`Es384`] (P-384).
//!
//! ECDSA is an asymmetric algorithm -- a private key signs and the
//! corresponding public key verifies. Keys can be constructed from raw scalar
//! bytes ([`signing_key_from_bytes`]) or SEC1-encoded public keys
//! ([`verifying_key_from_sec1`]).
//!
//! The root-level key functions target ES256. For ES384 use the [`es384`]
//! submodule.

pub use no_way_jose_core;

use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

// -- ES256 --

/// ES256: ECDSA using P-256 and SHA-256 (RFC 7518 Section 3.4).
pub struct Es256;

impl no_way_jose_core::__private::Sealed for Es256 {}

impl JwsAlgorithm for Es256 {
    const ALG: &'static str = "ES256";
}

impl HasKey<Signing> for Es256 {
    type Key = p256::ecdsa::SigningKey;
}

impl HasKey<Verifying> for Es256 {
    type Key = p256::ecdsa::VerifyingKey;
}

impl Signer for Es256 {
    fn sign(key: &p256::ecdsa::SigningKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for Es256 {
    fn verify(
        key: &p256::ecdsa::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        use p256::ecdsa::signature::Verifier;
        let sig =
            p256::ecdsa::Signature::from_slice(signature).map_err(|_| JoseError::CryptoError)?;
        key.verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

/// ES256 signing key.
pub type SigningKey = no_way_jose_core::SigningKey<Es256>;
/// ES256 verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es256>;

/// Create an ES256 signing key from a raw P-256 scalar (32 bytes).
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, JoseError> {
    p256::ecdsa::SigningKey::from_slice(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

/// Create an ES256 verifying key from SEC1-encoded public key bytes.
pub fn verifying_key_from_sec1(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

/// Derive the ES256 verifying key from a signing key.
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(*key.inner().verifying_key())
}

// -- ES384 --

/// ES384: ECDSA using P-384 and SHA-384 (RFC 7518 Section 3.4).
pub struct Es384;

impl no_way_jose_core::__private::Sealed for Es384 {}

impl JwsAlgorithm for Es384 {
    const ALG: &'static str = "ES384";
}

impl HasKey<Signing> for Es384 {
    type Key = p384::ecdsa::SigningKey;
}

impl HasKey<Verifying> for Es384 {
    type Key = p384::ecdsa::VerifyingKey;
}

impl Signer for Es384 {
    fn sign(key: &p384::ecdsa::SigningKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        use p384::ecdsa::signature::Signer;
        let sig: p384::ecdsa::Signature = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for Es384 {
    fn verify(
        key: &p384::ecdsa::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        use p384::ecdsa::signature::Verifier;
        let sig =
            p384::ecdsa::Signature::from_slice(signature).map_err(|_| JoseError::CryptoError)?;
        key.verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

pub mod es384 {
    use no_way_jose_core::JoseError;

    pub type SigningKey = no_way_jose_core::SigningKey<super::Es384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Es384>;

    pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, JoseError> {
        p384::ecdsa::SigningKey::from_slice(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| JoseError::InvalidKey)
    }

    pub fn verifying_key_from_sec1(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
        p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| JoseError::InvalidKey)
    }

    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(*key.inner().verifying_key())
    }
}

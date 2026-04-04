pub use jose_core;

use jose_core::JoseError;
use jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use jose_core::key::{HasKey, Signing, Verifying};

/// ES256: ECDSA using P-256 and SHA-256 (RFC 7518 Section 3.4).
pub struct Es256;

impl jose_core::sealed::Sealed for Es256 {}

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

pub type SigningKey = jose_core::SigningKey<Es256>;
pub type VerifyingKey = jose_core::VerifyingKey<Es256>;

pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, JoseError> {
    p256::ecdsa::SigningKey::from_slice(bytes)
        .map(jose_core::key::Key)
        .map_err(|_| JoseError::InvalidKey)
}

pub fn verifying_key_from_sec1(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map(jose_core::key::Key)
        .map_err(|_| JoseError::InvalidKey)
}

pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    jose_core::key::Key(*key.0.verifying_key())
}

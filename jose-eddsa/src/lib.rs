pub use jose_core;

use jose_core::JoseError;
use jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use jose_core::key::{HasKey, Signing, Verifying};

/// EdDSA: Edwards-curve Digital Signature Algorithm using Ed25519 (RFC 8037).
pub struct EdDsa;

impl jose_core::__private::Sealed for EdDsa {}

impl JwsAlgorithm for EdDsa {
    const ALG: &'static str = "EdDSA";
}

impl HasKey<Signing> for EdDsa {
    type Key = ed25519_dalek::SigningKey;
}

impl HasKey<Verifying> for EdDsa {
    type Key = ed25519_dalek::VerifyingKey;
}

impl Signer for EdDsa {
    fn sign(
        key: &ed25519_dalek::SigningKey,
        signing_input: &[u8],
    ) -> Result<Vec<u8>, JoseError> {
        use ed25519_dalek::Signer;
        let sig = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for EdDsa {
    fn verify(
        key: &ed25519_dalek::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        use ed25519_dalek::Verifier;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| JoseError::CryptoError)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        key.verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

pub type SigningKey = jose_core::SigningKey<EdDsa>;
pub type VerifyingKey = jose_core::VerifyingKey<EdDsa>;

pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    jose_core::key::Key::new(ed25519_dalek::SigningKey::from_bytes(bytes))
}

pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, JoseError> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map(jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    jose_core::key::Key::new(key.inner().verifying_key())
}

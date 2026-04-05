use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

use graviola::signing::eddsa;

/// EdDSA: Edwards-curve Digital Signature Algorithm using Ed25519 (graviola backend).
pub struct EdDsa;

impl no_way_jose_core::__private::Sealed for EdDsa {}

impl JwsAlgorithm for EdDsa {
    const ALG: &'static str = "EdDSA";
}

impl HasKey<Signing> for EdDsa {
    type Key = eddsa::Ed25519SigningKey;
}

impl HasKey<Verifying> for EdDsa {
    type Key = eddsa::Ed25519VerifyingKey;
}

impl Signer for EdDsa {
    fn sign(key: &eddsa::Ed25519SigningKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        Ok(key.sign(signing_input).to_vec())
    }
}

impl Verifier for EdDsa {
    fn verify(
        key: &eddsa::Ed25519VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        key.verify(signature, signing_input)
            .map_err(|_| JoseError::CryptoError)
    }
}

pub type SigningKey = no_way_jose_core::SigningKey<EdDsa>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<EdDsa>;

pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, JoseError> {
    eddsa::Ed25519SigningKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
    eddsa::Ed25519VerifyingKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(key.inner().public_key())
}

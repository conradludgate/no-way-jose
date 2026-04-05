//! EdDSA JWS algorithm using Ed25519 ([`EdDsa`]).
//!
//! EdDSA is an asymmetric algorithm with small, fast keys. Keys are
//! constructed from 32-byte seeds ([`signing_key_from_bytes`]) or raw
//! public key bytes ([`verifying_key_from_bytes`]).

#![no_std]

extern crate alloc;

pub use no_way_jose_core;

use alloc::vec::Vec;
use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

/// EdDSA: Edwards-curve Digital Signature Algorithm using Ed25519 (RFC 8037).
pub struct EdDsa;

impl no_way_jose_core::__private::Sealed for EdDsa {}

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
    fn sign(key: &ed25519_dalek::SigningKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
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
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| JoseError::CryptoError)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        key.verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

/// EdDSA signing key.
pub type SigningKey = no_way_jose_core::SigningKey<EdDsa>;
/// EdDSA verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<EdDsa>;

/// Create an EdDSA signing key from a 32-byte Ed25519 seed.
pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    no_way_jose_core::key::Key::new(ed25519_dalek::SigningKey::from_bytes(bytes))
}

/// Create an EdDSA verifying key from 32-byte Ed25519 public key bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, JoseError> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

/// Derive the EdDSA verifying key from a signing key.
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(key.inner().verifying_key())
}

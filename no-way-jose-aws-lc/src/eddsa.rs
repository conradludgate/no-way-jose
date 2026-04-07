use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use error_stack::Report;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

pub struct Ed25519VerifyingKey {
    bytes: Vec<u8>,
}

/// `EdDSA`: Edwards-curve Digital Signature Algorithm using Ed25519 (aws-lc-rs backend).
pub struct EdDsa;

impl JwsAlgorithm for EdDsa {
    const ALG: &'static str = "EdDSA";
}

impl HasKey<Signing> for EdDsa {
    type Key = Ed25519KeyPair;
}

impl HasKey<Verifying> for EdDsa {
    type Key = Ed25519VerifyingKey;
}

impl Signer for EdDsa {
    fn sign(key: &Ed25519KeyPair, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
        Ok(key.sign(signing_input).as_ref().to_vec())
    }
}

impl Verifier for EdDsa {
    fn verify(
        key: &Ed25519VerifyingKey,
        signing_input: &[u8],
        sig: &[u8],
    ) -> JoseResult<()> {
        let pk = UnparsedPublicKey::new(&signature::ED25519, &key.bytes);
        pk.verify(signing_input, sig)
            .map_err(|_| Report::new(JoseError::CryptoError))
    }
}

pub type SigningKey = no_way_jose_core::SigningKey<EdDsa>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<EdDsa>;

/// Create a signing key from a 32-byte Ed25519 seed.
///
/// # Errors
/// Returns [`JoseError::InvalidKey`] if the seed is invalid.
pub fn signing_key_from_seed(bytes: &[u8]) -> JoseResult<SigningKey> {
    Ed25519KeyPair::from_seed_unchecked(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// Create a signing key from PKCS#8 v2 DER bytes.
///
/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_pkcs8_der(bytes: &[u8]) -> JoseResult<SigningKey> {
    Ed25519KeyPair::from_pkcs8(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// Create a verifying key from the 32-byte Ed25519 public key.
///
/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key is not 32 bytes.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> JoseResult<VerifyingKey> {
    if bytes.len() != 32 {
        return Err(Report::new(JoseError::InvalidKey));
    }
    Ok(no_way_jose_core::key::Key::new(Ed25519VerifyingKey {
        bytes: bytes.to_vec(),
    }))
}

/// Extract the verifying key from a signing key pair.
#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(Ed25519VerifyingKey {
        bytes: key.inner().public_key().as_ref().to_vec(),
    })
}

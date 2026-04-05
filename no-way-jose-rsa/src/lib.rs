//! RSA PKCS#1 v1.5 JWS algorithm: [`Rs256`].
//!
//! RSA is an asymmetric algorithm. Keys are constructed from the `rsa` crate's
//! [`rsa::RsaPrivateKey`] and [`rsa::RsaPublicKey`] types via [`signing_key`]
//! and [`verifying_key`].

pub use no_way_jose_core;

use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

/// RS256: RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 Section 3.3).
pub struct Rs256;

impl no_way_jose_core::__private::Sealed for Rs256 {}

impl JwsAlgorithm for Rs256 {
    const ALG: &'static str = "RS256";
}

impl HasKey<Signing> for Rs256 {
    type Key = rsa::RsaPrivateKey;
}

impl HasKey<Verifying> for Rs256 {
    type Key = rsa::RsaPublicKey;
}

impl Signer for Rs256 {
    fn sign(key: &rsa::RsaPrivateKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_key = SigningKey::<sha2::Sha256>::new(key.clone());
        let sig = signing_key.sign(signing_input);
        Ok(sig.to_vec())
    }
}

impl Verifier for Rs256 {
    fn verify(
        key: &rsa::RsaPublicKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(key.clone());
        let sig =
            rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| JoseError::CryptoError)?;
        verifying_key
            .verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

/// RS256 signing key.
pub type SigningKey = no_way_jose_core::SigningKey<Rs256>;
/// RS256 verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Rs256>;

/// Create an RS256 signing key from an RSA private key.
pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
    no_way_jose_core::key::Key::new(private_key)
}

/// Create an RS256 verifying key from an RSA public key.
pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(public_key)
}

/// Derive the RS256 verifying key from a signing key.
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
}

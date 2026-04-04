pub use jose_core;

use hmac::{Hmac, Mac};
use jose_core::JoseError;
use jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use jose_core::key::{HasKey, Signing, Verifying};

/// HS256: HMAC using SHA-256 (RFC 7518 Section 3.2).
pub struct Hs256;

impl jose_core::__private::Sealed for Hs256 {}

impl JwsAlgorithm for Hs256 {
    const ALG: &'static str = "HS256";
}

/// Symmetric key for HS256. Signing and verifying use the same key.
#[derive(Clone)]
pub struct HmacKey(Vec<u8>);

impl HasKey<Signing> for Hs256 {
    type Key = HmacKey;
}

impl HasKey<Verifying> for Hs256 {
    type Key = HmacKey;
}

type HmacSha256 = Hmac<sha2::Sha256>;

impl Signer for Hs256 {
    fn sign(key: &HmacKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        let mut mac = HmacSha256::new_from_slice(&key.0).map_err(|_| JoseError::InvalidKey)?;
        mac.update(signing_input);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl Verifier for Hs256 {
    fn verify(key: &HmacKey, signing_input: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        let mut mac = HmacSha256::new_from_slice(&key.0).map_err(|_| JoseError::InvalidKey)?;
        mac.update(signing_input);
        mac.verify_slice(signature)
            .map_err(|_| JoseError::CryptoError)
    }
}

pub type SigningKey = jose_core::SigningKey<Hs256>;
pub type VerifyingKey = jose_core::VerifyingKey<Hs256>;

/// RFC 7518 §3.2: HMAC key MUST be at least as long as the hash output (32 bytes for HS256).
const MIN_KEY_LEN: usize = 32;

pub fn symmetric_key(bytes: impl Into<Vec<u8>>) -> Result<SigningKey, JoseError> {
    let bytes = bytes.into();
    if bytes.len() < MIN_KEY_LEN {
        return Err(JoseError::InvalidKey);
    }
    Ok(jose_core::key::Key::new(HmacKey(bytes)))
}

pub fn verifying_key(bytes: impl Into<Vec<u8>>) -> Result<VerifyingKey, JoseError> {
    let bytes = bytes.into();
    if bytes.len() < MIN_KEY_LEN {
        return Err(JoseError::InvalidKey);
    }
    Ok(jose_core::key::Key::new(HmacKey(bytes)))
}

use alloc::vec::Vec;

use crate::__private::Sealed;
use crate::JoseError;
use crate::key::{HasKey, KeyInner, Signing, Verifying};

/// Marker trait for JWS algorithm identifiers.
pub trait JwsAlgorithm: Sealed + Send + Sync + Sized + 'static {
    const ALG: &'static str;
}

/// This algorithm can produce signatures.
pub trait Signer: JwsAlgorithm + HasKey<Signing> {
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] if signing fails.
    fn sign(key: &KeyInner<Self, Signing>, signing_input: &[u8]) -> Result<Vec<u8>, JoseError>;
}

/// This algorithm can verify signatures.
pub trait Verifier: JwsAlgorithm + HasKey<Verifying> {
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] if the signature is invalid.
    fn verify(
        key: &KeyInner<Self, Verifying>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError>;
}

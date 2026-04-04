use alloc::vec::Vec;

use crate::JoseError;
use crate::key::{HasKey, KeyInner, Signing, Verifying};
use crate::sealed::Sealed;

/// Marker trait for JWS algorithm identifiers.
pub trait JwsAlgorithm: Sealed + Send + Sync + Sized + 'static {
    const ALG: &'static str;
}

/// This algorithm can produce signatures.
pub trait Signer: JwsAlgorithm + HasKey<Signing> {
    fn sign(key: &KeyInner<Self, Signing>, signing_input: &[u8]) -> Result<Vec<u8>, JoseError>;
}

/// This algorithm can verify signatures.
pub trait Verifier: JwsAlgorithm + HasKey<Verifying> {
    fn verify(
        key: &KeyInner<Self, Verifying>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError>;
}

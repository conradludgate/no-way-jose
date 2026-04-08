//! JWS algorithm traits.
//!
//! A signing algorithm is defined by implementing three traits on a zero-sized type:
//!
//! - [`JwsAlgorithm`] — declares the `alg` header value (e.g. `"HS256"`)
//! - [`Signer`] — produces a signature from a signing key and the signing input
//! - [`Verifier`] — checks a signature against a verifying key
//!
//! The key types are determined by the algorithm via [`HasKey<Signing>`](crate::key::HasKey)
//! and [`HasKey<Verifying>`](crate::key::HasKey). Core provides only the traits;
//! concrete implementations live in algorithm crates like `no-way-jose-hmac`.

use alloc::vec::Vec;

use crate::JoseResult;
use crate::key::{HasKey, KeyInner, Signing, Verifying};

/// Marker trait for JWS algorithm identifiers.
pub trait JwsAlgorithm: Send + Sync + Sized + 'static {
    const ALG: &'static str;
}

/// This algorithm can produce signatures.
pub trait Signer: JwsAlgorithm + HasKey<Signing> {
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] if signing fails.
    fn sign(key: &KeyInner<Self, Signing>, signing_input: &[u8]) -> JoseResult<Vec<u8>>;
}

/// This algorithm can verify signatures.
pub trait Verifier: JwsAlgorithm + HasKey<Verifying> {
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] if the signature is invalid.
    fn verify(
        key: &KeyInner<Self, Verifying>,
        signing_input: &[u8],
        signature: &[u8],
    ) -> JoseResult<()>;
}

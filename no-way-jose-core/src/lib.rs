//! Core types and traits for the no-way-jose JOSE library.
//!
//! This crate defines the token lifecycle (`UnsealedToken` -> sign/encrypt ->
//! `CompactToken` -> verify/decrypt -> `UnsealedToken`), the key system, JSON
//! encoding traits, and the validation framework. It is `no_std`-compatible and
//! has no cryptographic dependencies -- algorithm implementations live in
//! separate crates.
//!
//! Most users will interact with the type aliases at the crate root:
//!
//! - **JWS:** [`CompactJws`], [`UnsignedToken`], [`SigningKey`], [`VerifyingKey`]
//! - **JWE:** [`CompactJwe`], [`EncryptionKey`], [`DecryptionKey`]
//! - **Dynamic:** [`UntypedCompactJws`] for runtime algorithm selection

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod algorithm;
pub(crate) mod base64url;
pub mod dir;
pub mod header;
pub mod json;
pub mod jwe_algorithm;
pub mod key;
pub mod purpose;
pub mod tokens;
pub mod validation;

#[doc(hidden)]
pub mod __private {
    pub trait Sealed {}
}

use alloc::boxed::Box;
use core::error::Error;

/// Private key used for JWS signing, parameterized by algorithm.
pub type SigningKey<A> = key::Key<A, key::Signing>;

/// Public key used for JWS verification, parameterized by algorithm.
pub type VerifyingKey<A> = key::Key<A, key::Verifying>;

/// A parsed, unverified JWS compact token (`header.payload.signature`).
pub type CompactJws<A, M = json::RawJson> = tokens::CompactJws<A, M>;

/// A JWS token before signing (or after successful verification).
pub type UnsignedToken<A, M> = tokens::UnsignedToken<A, M>;

/// A parsed JWS token whose algorithm is determined at runtime.
pub type UntypedCompactJws<M = json::RawJson> = tokens::UntypedCompactJws<M>;

/// Key used for JWE encryption (wrapping or providing the CEK).
pub type EncryptionKey<KM> = key::Key<KM, key::Encrypting>;

/// Key used for JWE decryption (unwrapping or receiving the CEK).
pub type DecryptionKey<KM> = key::Key<KM, key::Decrypting>;

/// A parsed, undecrypted JWE compact token (`header.ek.iv.ciphertext.tag`).
pub type CompactJwe<KM, CE, M = json::RawJson> = tokens::CompactJwe<KM, CE, M>;

/// Errors returned by token operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum JoseError {
    /// Base64url decoding failed.
    Base64DecodeError,
    /// The key material is invalid or too short.
    InvalidKey,
    /// The token structure or header is malformed.
    InvalidToken(&'static str),
    /// Signature verification or decryption failed.
    CryptoError,
    /// Claims validation failed (expiry, issuer, audience, etc.).
    ClaimsError(&'static str),
    /// The payload could not be serialized or deserialized.
    PayloadError(Box<dyn Error + Send + Sync>),
}

impl Error for JoseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            JoseError::PayloadError(x) => Some(&**x),
            _ => None,
        }
    }
}

impl core::fmt::Display for JoseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            JoseError::Base64DecodeError => f.write_str("could not base64url-decode the token"),
            JoseError::InvalidKey => f.write_str("could not parse the key"),
            JoseError::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            JoseError::CryptoError => f.write_str("signature or decryption verification failed"),
            JoseError::ClaimsError(msg) => write!(f, "claims validation failed: {msg}"),
            JoseError::PayloadError(x) => write!(f, "payload encoding error: {x}"),
        }
    }
}

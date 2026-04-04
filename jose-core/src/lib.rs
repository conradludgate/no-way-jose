#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod algorithm;
pub mod key;
pub mod purpose;

mod sealed {
    pub trait Sealed {}
}

use alloc::boxed::Box;
use core::error::Error;

/// Type aliases for JWS tokens.
pub type SigningKey<A> = key::Key<A, key::Signing>;
pub type VerifyingKey<A> = key::Key<A, key::Verifying>;

#[derive(Debug)]
#[non_exhaustive]
pub enum JoseError {
    Base64DecodeError,
    InvalidKey,
    InvalidToken,
    CryptoError,
    ClaimsError,
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
            JoseError::InvalidToken => f.write_str("could not parse the token"),
            JoseError::CryptoError => f.write_str("signature or decryption verification failed"),
            JoseError::ClaimsError => f.write_str("token claims failed validation"),
            JoseError::PayloadError(x) => write!(f, "payload encoding error: {x}"),
        }
    }
}

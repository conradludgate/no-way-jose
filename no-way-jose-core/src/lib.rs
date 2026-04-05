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

pub type SigningKey<A> = key::Key<A, key::Signing>;
pub type VerifyingKey<A> = key::Key<A, key::Verifying>;

pub type CompactJws<A, M = json::RawJson> = tokens::CompactJws<A, M>;
pub type UnsignedToken<A, M> = tokens::UnsignedToken<A, M>;
pub type UntypedCompactJws<M = json::RawJson> = tokens::UntypedCompactJws<M>;

pub type EncryptionKey<KM> = key::Key<KM, key::Encrypting>;
pub type DecryptionKey<KM> = key::Key<KM, key::Decrypting>;
pub type CompactJwe<KM, CE, M = json::RawJson> = tokens::CompactJwe<KM, CE, M>;

#[derive(Debug)]
#[non_exhaustive]
pub enum JoseError {
    Base64DecodeError,
    InvalidKey,
    InvalidToken(&'static str),
    CryptoError,
    ClaimsError(&'static str),
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

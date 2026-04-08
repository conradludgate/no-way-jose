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
//! - **JWE:** [`CompactJwe`], [`EncryptionKey`]
//! - **Dynamic:** [`UntypedCompactJws`], [`UntypedCompactJwe`] for runtime algorithm selection

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod docs;

pub mod algorithm;
pub mod base64url;
pub mod dir;
pub mod error;
pub mod header;
pub mod json;
pub mod jwe_algorithm;
pub mod jwk;
pub mod key;
pub mod purpose;
pub mod tokens;
pub mod validation;

pub use error::*;

mod __private {
    pub trait Sealed {}
}

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

/// Fluent builder for constructing tokens with optional header fields (kid, typ).
pub type TokenBuilder<P, M> = tokens::TokenBuilder<P, M>;

/// Key used for JWE key management (wrapping/unwrapping the CEK).
pub type EncryptionKey<KM> = key::Key<KM, key::Encrypting>;

/// A parsed, undecrypted JWE compact token (`header.ek.iv.ciphertext.tag`).
pub type CompactJwe<KM, CE, M = json::RawJson> = tokens::CompactJwe<KM, CE, M>;

/// A parsed JWE token whose algorithms are determined at runtime.
pub type UntypedCompactJwe<M = json::RawJson> = tokens::UntypedCompactJwe<M>;

//! Core types and traits for the [no-way-jose](https://github.com/conradludgate/no-way-jose) JOSE library.
//!
//! This crate is `no_std`-compatible and contains no cryptographic code.
//! It defines the token types, algorithm traits, key system, JSON encoding,
//! JWK support, and validation framework. Algorithm implementations live in
//! separate crates — see the [`docs::_03_algorithms`] module for a full list.
//!
//! ## Key types
//!
//! - **JWS:** [`CompactJws`], [`UnsignedToken`], [`SigningKey`], [`VerifyingKey`]
//! - **JWE:** [`CompactJwe`], [`EncryptionKey`]
//! - **Dynamic dispatch:** [`UntypedCompactJws`], [`UntypedCompactJwe`]
//! - **Headers:** [`TokenBuilder`] for setting `kid`, `typ`, `cty`
//! - **JWK:** [`jwk::Jwk`], [`jwk::JwkSet`], [`jwk::ToJwk`], [`jwk::FromJwk`]
//!
//! ## Documentation
//!
//! See the [`docs`] module for:
//! - [Architecture](docs::_01_architecture) — design decisions, type safety, trait hierarchy
//! - [How-to guides](docs::_02_howto) — sign, verify, encrypt, decrypt, custom claims, JWK
//! - [Algorithm table](docs::_03_algorithms) — every algorithm crate with links
//!
//! For JWT registered claims (`exp`, `iss`, `aud`, ...) and validators, see
//! [`no-way-jose-claims`](https://docs.rs/no-way-jose-claims).

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

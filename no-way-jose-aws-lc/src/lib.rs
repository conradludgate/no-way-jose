//! [aws-lc-rs](https://crates.io/crates/aws-lc-rs) crypto backend for
//! [`no-way-jose`](https://crates.io/crates/no-way-jose-core).
//!
//! Re-implements the same algorithm traits as the default RustCrypto-based
//! crates, but backed by AWS-LC — the cryptography library used by AWS.
//! FIPS 140-3 validated builds are available via the `aws-lc-rs` `fips`
//! feature. Tokens produced by any backend are interchangeable on the wire.
//!
//! ## Algorithms
//!
//! | Module | Algorithms |
//! |--------|-----------|
//! | [`hmac`] | HS256, HS384, HS512 |
//! | [`ecdsa`] | ES256, ES384, ES512 |
//! | [`eddsa`] | `EdDSA` (Ed25519) |
//! | [`rsa`] | RS256, RS384, RS512, PS256, PS384, PS512 |
//! | [`aes_gcm`] | A128GCM, A256GCM |
//!
//! All algorithm types implement [`JwkKeyConvert`](no_way_jose_core::jwk::JwkKeyConvert)
//! for JWK import/export.

#![warn(clippy::pedantic)]

pub use no_way_jose_core;

pub mod aes_gcm;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;

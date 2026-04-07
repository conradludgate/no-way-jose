//! [Graviola](https://crates.io/crates/graviola) crypto backend for
//! [`no-way-jose`](https://crates.io/crates/no-way-jose-core).
//!
//! Re-implements the same algorithm traits as the default RustCrypto-based
//! crates, but backed by graviola — a cryptography library with formally
//! verified assembler routines. Tokens produced by either backend are
//! interchangeable on the wire.
//!
//! ## Algorithms
//!
//! | Module | Algorithms |
//! |--------|-----------|
//! | [`hmac`] | HS256, HS384, HS512 |
//! | [`ecdsa`] | ES256, ES384 |
//! | [`eddsa`] | `EdDSA` (Ed25519) |
//! | [`rsa`] | RS256, PS256 |
//! | [`aes_gcm`] | A128GCM, A256GCM |
//!
//! ## Platform requirements
//!
//! Requires **aarch64** or **x86\_64** with specific CPU features.
//! See the [graviola docs](https://docs.rs/graviola) for details.

#![warn(clippy::pedantic)]

pub use no_way_jose_core;

pub mod aes_gcm;
pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;

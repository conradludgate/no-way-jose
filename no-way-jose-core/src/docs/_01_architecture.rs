//! # Architecture
//!
//! ## Type-level algorithm safety
//!
//! Every algorithm is a zero-sized type (ZST) such as `Hs256`, `Es256`, or
//! `A256Gcm`. Keys are parameterized by both the algorithm and a purpose marker
//! ([`Signing`], [`Verifying`], or [`Encrypting`]), so the compiler prevents
//! mismatches before your code runs:
//!
//! ```text
//! SigningKey<Hs256>   + CompactJws<Hs256>   ✓ compiles
//! SigningKey<Hs256>   + CompactJws<Es256>   ✗ type error
//! VerifyingKey<Hs256> + sign()              ✗ type error
//! ```
//!
//! [`Signing`]: crate::key::Signing
//! [`Verifying`]: crate::key::Verifying
//! [`Encrypting`]: crate::key::Encrypting
//!
//! ## Modular crate structure
//!
//! `no-way-jose-core` contains no cryptographic code. It defines the traits
//! that algorithm crates implement, the token types that orchestrate the
//! sign/verify/encrypt/decrypt flow, and the JSON and JWK machinery.
//!
//! Each algorithm family lives in its own crate (e.g. `no-way-jose-hmac`,
//! `no-way-jose-ecdsa`). You depend only on the algorithms you use. The
//! traits are public, so third-party crates can provide additional algorithms
//! or alternative crypto backends.
//!
//! ## No serde
//!
//! JOSE payloads are compact JSON with no whitespace. Rather than depending on
//! serde, this library provides [`ToJson`] and [`FromJson`] traits backed by a
//! minimal [`JsonWriter`] and [`JsonReader`]. This keeps the dependency tree
//! small and gives precise control over the wire format.
//!
//! [`ToJson`]: crate::json::ToJson
//! [`FromJson`]: crate::json::FromJson
//! [`JsonWriter`]: crate::json::JsonWriter
//! [`JsonReader`]: crate::json::JsonReader
//!
//! ## JWS trait stack
//!
//! A JWS signing algorithm implements three traits:
//!
//! - [`JwsAlgorithm`] — declares the `alg` header value (e.g. `"HS256"`)
//! - [`Signer`] — produces a signature from a signing key and input bytes
//! - [`Verifier`] — checks a signature against a verifying key
//!
//! [`JwsAlgorithm`]: crate::algorithm::JwsAlgorithm
//! [`Signer`]: crate::algorithm::Signer
//! [`Verifier`]: crate::algorithm::Verifier
//!
//! ## JWE trait stack
//!
//! JWE has two independent trait stacks — one for key management, one for
//! content encryption:
//!
//! **Key management** (how the Content Encryption Key is wrapped/unwrapped):
//! - [`JweKeyManagement`] — declares the `alg` header value
//! - [`KeyManager`] — encrypts and decrypts the CEK
//!
//! **Content encryption** (how the payload is encrypted):
//! - [`JweContentEncryption`] — declares the `enc` header value and key/IV sizes
//! - [`ContentCipher`] — performs authenticated encryption and decryption
//!
//! A JWE token is parameterized by both: `CompactJwe<KM, CE>` where `KM`
//! implements `KeyManager` and `CE` implements `ContentCipher`.
//!
//! [`JweKeyManagement`]: crate::jwe_algorithm::JweKeyManagement
//! [`KeyManager`]: crate::jwe_algorithm::KeyManager
//! [`JweContentEncryption`]: crate::jwe_algorithm::JweContentEncryption
//! [`ContentCipher`]: crate::jwe_algorithm::ContentCipher
//!
//! ## Token lifecycle
//!
//! ### JWS
//!
//! ```text
//! UnsignedToken::new(claims)
//!       │
//!       ▼  .sign(&signing_key)
//!  CompactJws  ←──  token_string.parse()
//!       │
//!       ▼  .verify(&verifying_key, &validator)
//! UnsealedToken { claims }
//! ```
//!
//! ### JWE
//!
//! ```text
//! UnsealedToken::new(claims)
//!       │
//!       ▼  .encrypt(&encryption_key)
//!  CompactJwe  ←──  token_string.parse()
//!       │
//!       ▼  .decrypt(&encryption_key, &validator)
//! UnsealedToken { claims }
//! ```
//!
//! ## Validation
//!
//! The [`Validate`] trait defines claim checks that run after
//! signature verification or decryption. Validators compose with
//! [`and_then`](crate::validation::Validate::and_then):
//!
//! ```text
//! HasExpiry.and_then(Time::valid_now()).and_then(ForAudience("my-api"))
//! ```
//!
//! [`NoValidation`] is an escape hatch that skips all checks — the caller
//! takes responsibility for validating claims.
//!
//! [`Validate`]: crate::validation::Validate
//! [`NoValidation`]: crate::validation::NoValidation

//! # Algorithm crates
//!
//! Each algorithm family lives in its own crate. Pick only the ones you need.
//!
//! ## JWS signing
//!
//! | Algorithm | Crate | RFC |
//! |-----------|-------|-----|
//! | HS256, HS384, HS512 | [`no-way-jose-hmac`](https://docs.rs/no-way-jose-hmac) | 7518 §3.2 |
//! | ES256, ES384, ES512 | [`no-way-jose-ecdsa`](https://docs.rs/no-way-jose-ecdsa) | 7518 §3.4 |
//! | EdDSA (Ed25519) | [`no-way-jose-eddsa`](https://docs.rs/no-way-jose-eddsa) | 8037 |
//! | RS256–RS512, PS256–PS512 | [`no-way-jose-rsa`](https://docs.rs/no-way-jose-rsa) | 7518 §3.3/§3.5 |
//!
//! ## JWE key management
//!
//! | Algorithm | Crate | RFC |
//! |-----------|-------|-----|
//! | dir | [`no-way-jose-core`](crate::dir) (built-in) | 7518 §4.5 |
//! | A128KW, A192KW, A256KW | [`no-way-jose-aes-kw`](https://docs.rs/no-way-jose-aes-kw) | 7518 §4.4 |
//! | A128GCMKW, A192GCMKW, A256GCMKW | [`no-way-jose-aes-gcm-kw`](https://docs.rs/no-way-jose-aes-gcm-kw) | 7518 §4.7 |
//! | RSA1\_5, RSA-OAEP, RSA-OAEP-256 | [`no-way-jose-rsa`](https://docs.rs/no-way-jose-rsa) | 7518 §4.2/§4.3 |
//! | ECDH-ES, ECDH-ES+AxxxKW | [`no-way-jose-ecdh-es`](https://docs.rs/no-way-jose-ecdh-es) | 7518 §4.6 |
//! | PBES2-HSxxx+AxxxKW | [`no-way-jose-pbes2`](https://docs.rs/no-way-jose-pbes2) | 7518 §4.8 |
//!
//! ## JWE content encryption
//!
//! | Algorithm | Crate | RFC |
//! |-----------|-------|-----|
//! | A128GCM, A192GCM, A256GCM | [`no-way-jose-aes-gcm`](https://docs.rs/no-way-jose-aes-gcm) | 7518 §5.3 |
//! | A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 | [`no-way-jose-aes-cbc-hs`](https://docs.rs/no-way-jose-aes-cbc-hs) | 7518 §5.2 |
//!
//! ## Alternative crypto backends
//!
//! The crates above use [RustCrypto](https://github.com/RustCrypto) by default.
//! Two alternative backends provide the same traits and produce wire-compatible
//! tokens:
//!
//! | Backend | Crate | Notes |
//! |---------|-------|-------|
//! | [Graviola](https://crates.io/crates/graviola) | [`no-way-jose-graviola`](https://docs.rs/no-way-jose-graviola) | Formally verified assembler; aarch64/x86\_64 only |
//! | [aws-lc-rs](https://crates.io/crates/aws-lc-rs) | [`no-way-jose-aws-lc`](https://docs.rs/no-way-jose-aws-lc) | FIPS 140-3 validated builds available |
//!
//! ## JWT claims
//!
//! [`no-way-jose-claims`](https://docs.rs/no-way-jose-claims) provides
//! [`RegisteredClaims`](https://docs.rs/no-way-jose-claims/latest/no_way_jose_claims/struct.RegisteredClaims.html)
//! (RFC 7519 §4.1) and composable validators (`HasExpiry`, `Time`,
//! `FromIssuer`, `ForAudience`). It is the only crate in the workspace that
//! requires `std`.

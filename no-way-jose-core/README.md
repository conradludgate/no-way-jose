# no-way-jose-core

Core types and traits for the [no-way-jose](https://github.com/conradludgate/no-way-jose) JOSE library.

This crate provides the foundation that all algorithm crates build on:

- **Token types** — `CompactJws`, `CompactJwe`, `UnsignedToken`, `UnsealedToken`, and their untyped counterparts for runtime algorithm dispatch.
- **Algorithm traits** — `JwsAlgorithm`, `Signer`, `Verifier`, `JweKeyManagement`, `JweContentEncryption`, and related key traits.
- **JWK** — `Jwk`, `JwkSet`, `ToJwk`, `FromJwk`, and thumbprint computation (RFC 7638).
- **JSON** — A minimal `no_std`-compatible JSON reader/writer. Claim types implement `ToJson`/`FromJson` directly instead of using serde.
- **Validation** — The `Validate` trait and `NoValidation` for composable claim checks.
- **`dir` key management** — Direct key agreement (RFC 7518 §4.5).
- **Base64url** — Encoding/decoding helpers.

This crate is `#![no_std]` with `alloc`.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for usage examples and the full algorithm table.

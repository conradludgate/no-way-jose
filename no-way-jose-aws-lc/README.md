# no-way-jose-aws-lc

[aws-lc-rs](https://crates.io/crates/aws-lc-rs) crypto backend for [no-way-jose](https://github.com/conradludgate/no-way-jose).

Provides the same algorithm interfaces as the default RustCrypto-based crates, but backed by AWS-LC — the cryptography library used by AWS, with FIPS 140-3 validated builds available.

### Algorithms

| Category | Algorithms |
|----------|-----------|
| JWS signing | HS256, HS384, HS512, ES256, ES384, ES512, EdDSA, RS256, RS384, RS512, PS256, PS384, PS512 |
| JWE content encryption | A128GCM, A256GCM |

All algorithm types implement `JwkKeyConvert` for JWK import/export (HMAC, ECDSA, EdDSA, RSA verifying keys).

### Usage

Use `no_way_jose_aws_lc::hmac::Hs256` (etc.) as a drop-in replacement for `no_way_jose_hmac::Hs256`. Tokens are wire-compatible across backends.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for full examples.

# no-way-jose-graviola

[Graviola](https://crates.io/crates/graviola) crypto backend for [no-way-jose](https://github.com/conradludgate/no-way-jose).

Provides the same algorithm interfaces as the default RustCrypto-based crates, but backed by graviola — a cryptography library with formally verified assembler routines.

### Algorithms

| Category | Algorithms |
|----------|-----------|
| JWS signing | HS256, HS384, HS512, ES256, ES384, EdDSA, RS256, PS256 |
| JWE content encryption | A128GCM, A256GCM |

All algorithm types implement `JwkKeyConvert` for JWK import/export (HMAC, ECDSA, EdDSA).

### Platform requirements

Graviola requires **aarch64** or **x86\_64** with specific CPU features. See the [graviola docs](https://docs.rs/graviola) for details.

### Usage

Use `no_way_jose_graviola::hmac::Hs256` (etc.) as a drop-in replacement for `no_way_jose_hmac::Hs256`. Tokens are wire-compatible across backends.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for full examples.

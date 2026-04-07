# no-way-jose-hmac

HMAC-SHA JWS signing algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | Description | Min key length |
|-----------|-------------|----------------|
| HS256 | HMAC-SHA-256 | 32 bytes |
| HS384 | HMAC-SHA-384 | 48 bytes |
| HS512 | HMAC-SHA-512 | 64 bytes |

Uses the [RustCrypto](https://github.com/RustCrypto) `hmac` and `sha2` crates. `#![no_std]` compatible.

Implements `JwkKeyConvert` for JWK import/export of symmetric (`oct`) keys.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for usage examples.

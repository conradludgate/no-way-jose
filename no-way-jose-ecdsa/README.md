# no-way-jose-ecdsa

ECDSA JWS signing algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | Curve | Signature size |
|-----------|-------|----------------|
| ES256 | P-256 | 64 bytes |
| ES384 | P-384 | 96 bytes |
| ES512 | P-521 | 132 bytes |

Uses the [RustCrypto](https://github.com/RustCrypto) `p256`, `p384`, and `p521` crates. `#![no_std]` compatible.

Implements `JwkKeyConvert` for JWK import/export of EC keys (signing and verifying).

See the [workspace README](https://github.com/conradludgate/no-way-jose) for usage examples.

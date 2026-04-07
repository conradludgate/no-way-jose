# no-way-jose-eddsa

EdDSA (Ed25519) JWS signing algorithm for [no-way-jose](https://github.com/conradludgate/no-way-jose).

Uses [ed25519-dalek](https://docs.rs/ed25519-dalek) for Ed25519 signatures (RFC 8037). `#![no_std]` compatible.

Implements `JwkKeyConvert` for JWK import/export of OKP (Ed25519) keys.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for usage examples.

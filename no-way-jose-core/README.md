# no-way-jose-core

Core types and traits for the [no-way-jose](https://github.com/conradludgate/no-way-jose) JOSE library.

This crate is `#![no_std]` with `alloc` and contains no cryptographic code.
It defines the token types, algorithm traits, key system, JSON encoding,
JWK support, and validation framework. Algorithm implementations live in
separate crates.

## Key types

- **JWS:** `CompactJws`, `UnsignedToken`, `SigningKey`, `VerifyingKey`
- **JWE:** `CompactJwe`, `EncryptionKey`
- **Dynamic dispatch:** `UntypedCompactJws`, `UntypedCompactJwe`
- **Headers:** `TokenBuilder` for setting `kid`, `typ`, `cty`
- **JWK:** `Jwk`, `JwkSet`, `ToJwk`, `FromJwk`

## Documentation

The [`docs`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/docs/index.html) module
contains longer-form content:

- [Architecture](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/docs/_01_architecture/index.html) — design decisions, type safety, trait hierarchy
- [How-to guides](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/docs/_02_howto/index.html) — sign, verify, encrypt, decrypt, custom claims, JWK
- [Algorithm table](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/docs/_03_algorithms/index.html) — every algorithm crate with links

For JWT registered claims and validators, see
[no-way-jose-claims](https://docs.rs/no-way-jose-claims).

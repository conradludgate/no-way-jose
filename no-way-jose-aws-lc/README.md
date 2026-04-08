# no-way-jose-aws-lc

[aws-lc-rs](https://crates.io/crates/aws-lc-rs) crypto backend for [no-way-jose-core](https://docs.rs/no-way-jose-core): the same JWS/JWE algorithm traits as the default `RustCrypto` crates, backed by AWS-LC (tokens are interchangeable on the wire).

## Algorithms

| Module | Algorithms |
|--------|-----------|
| `hmac` | HS256, HS384, HS512 |
| `ecdsa` | ES256, ES384, ES512 |
| `eddsa` | EdDSA (Ed25519) |
| `rsa` | RS256, RS384, RS512, PS256, PS384, PS512 |
| `aes_gcm` | A128GCM, A256GCM |

All algorithm types implement `JwkKeyConvert` for JWK import/export.

## Drop-in usage

Swap this crate’s algorithm types (for example `hmac::Hs256`) for the matching types in [no-way-jose-hmac](https://docs.rs/no-way-jose-hmac) and related crates; the compact JWS format is unchanged.

```rust
use no_way_jose_core::json::RawJson;
use no_way_jose_core::validation::NoValidation;
use no_way_jose_core::{CompactJws, UnsignedToken};
use no_way_jose_aws_lc::hmac::Hs256;

let secret = b"my-secret-key-at-least-32-bytes!".to_vec();
let sk = no_way_jose_aws_lc::hmac::hs256::symmetric_key(secret.clone()).unwrap();
let vk = no_way_jose_aws_lc::hmac::hs256::verifying_key(secret).unwrap();

let token_str = UnsignedToken::<Hs256, RawJson>::new(RawJson(r#"{"sub":"alice"}"#.into()))
    .sign(&sk)
    .unwrap()
    .to_string();

let token: CompactJws<Hs256> = token_str.parse().unwrap();
let verified = token
    .verify(&vk, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(verified.claims.0, r#"{"sub":"alice"}"#);
```

## FIPS 140-3

FIPS 140-3 validated cryptography is available when `aws-lc-rs` is built with its `fips` feature (see the [aws-lc-rs documentation](https://docs.rs/aws-lc-rs)).

## See also

- [no-way-jose-core](https://docs.rs/no-way-jose-core) — tokens, keys, wire format
- [no-way-jose-claims](https://docs.rs/no-way-jose-claims) — common claim types and checks
- Default `RustCrypto` algorithm crates: [no-way-jose-hmac](https://docs.rs/no-way-jose-hmac), [no-way-jose-ecdsa](https://docs.rs/no-way-jose-ecdsa), [no-way-jose-eddsa](https://docs.rs/no-way-jose-eddsa), [no-way-jose-rsa](https://docs.rs/no-way-jose-rsa), [no-way-jose-aes-gcm](https://docs.rs/no-way-jose-aes-gcm)

# no-way-jose-hmac

HMAC-based JWS algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose): **HS256**, **HS384**, and **HS512** ([`Hs256`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/struct.Hs256.html), [`Hs384`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/struct.Hs384.html), [`Hs512`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/struct.Hs512.html)).

## Algorithms

| JWS `alg` | Construction | Minimum key length | Specification |
|-----------|--------------|-------------------|---------------|
| HS256 | HMAC-SHA-256 | 32 bytes | [RFC 7518 § 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) |
| HS384 | HMAC-SHA-384 | 48 bytes | [RFC 7518 § 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) |
| HS512 | HMAC-SHA-512 | 64 bytes | [RFC 7518 § 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2) |

HMAC is symmetric: the same secret signs and verifies. The crate-root [`symmetric_key`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/fn.symmetric_key.html) and [`verifying_key`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/fn.verifying_key.html) target HS256; use [`hs384`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/hs384/index.html) or [`hs512`](https://docs.rs/no-way-jose-hmac/latest/no_way_jose_hmac/hs512/index.html) for the other algorithms.

Uses the [RustCrypto](https://github.com/RustCrypto) `hmac` and `sha2` crates. `#![no_std]` compatible. Implements `JwkKeyConvert` for JWK import/export of symmetric (`oct`) keys.

## Example

```rust
use no_way_jose_core::json::RawJson;
use no_way_jose_core::validation::NoValidation;
use no_way_jose_core::{CompactJws, UnsignedToken};
use no_way_jose_hmac::hs256;
use no_way_jose_hmac::Hs256;

let secret = b"my-secret-key-at-least-32-bytes!".to_vec();
let sk = hs256::symmetric_key(secret.clone()).unwrap();
let vk = hs256::verifying_key(secret).unwrap();

let payload = r#"{"sub":"alice"}"#;
let claims = RawJson(payload.into());
let token_str = UnsignedToken::<Hs256, _>::new(claims)
    .sign(&sk)
    .unwrap()
    .to_string();

let token: CompactJws<Hs256> = token_str.parse().unwrap();
let verified = token
    .verify(&vk, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(verified.claims.0, payload);
```

See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

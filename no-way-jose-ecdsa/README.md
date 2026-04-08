# no-way-jose-ecdsa

ECDSA-based JWS algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose): **ES256**, **ES384**, and **ES512** ([`Es256`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/struct.Es256.html), [`Es384`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/struct.Es384.html), [`Es512`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/struct.Es512.html)).

## Algorithms

| JWS `alg` | Curve | Signature size (fixed) | Specification |
|-----------|-------|------------------------|---------------|
| ES256 | NIST P-256 (secp256r1) | 64 bytes | [RFC 7518 § 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4) |
| ES384 | NIST P-384 | 96 bytes | [RFC 7518 § 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4) |
| ES512 | NIST P-521 | 132 bytes | [RFC 7518 § 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4) |

ECDSA is asymmetric: a signing key produces signatures; the matching verifying key checks them. For ES256 use [`es256::signing_key`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/es256/fn.signing_key.html) (random, requires OS randomness via the `p256` `getrandom` feature) or [`signing_key_from_bytes`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/fn.signing_key_from_bytes.html); for ES384 / ES512 use [`es384`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/es384/index.html) and [`es512`](https://docs.rs/no-way-jose-ecdsa/latest/no_way_jose_ecdsa/es512/index.html).

Uses the [RustCrypto](https://github.com/RustCrypto) `p256`, `p384`, and `p521` crates. `#![no_std]` compatible. Implements `JwkKeyConvert` for JWK import/export of EC keys.

## Example

```rust
use no_way_jose_core::json::RawJson;
use no_way_jose_core::validation::NoValidation;
use no_way_jose_core::{CompactJws, UnsignedToken};
use no_way_jose_ecdsa::es256;
use no_way_jose_ecdsa::Es256;

let sk = es256::signing_key();
let vk = es256::verifying_key_from_signing(&sk);

let payload = r#"{"sub":"alice"}"#;
let claims = RawJson(payload.into());
let token_str = UnsignedToken::<Es256, _>::new(claims)
    .sign(&sk)
    .unwrap()
    .to_string();

let token: CompactJws<Es256> = token_str.parse().unwrap();
let verified = token
    .verify(&vk, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(verified.claims.0, payload);
```

See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

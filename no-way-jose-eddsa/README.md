# no-way-jose-eddsa

EdDSA (Ed25519) JWS algorithm for [no-way-jose](https://github.com/conradludgate/no-way-jose) ([`EdDsa`](https://docs.rs/no-way-jose-eddsa/latest/no_way_jose_eddsa/struct.EdDsa.html)).

## Algorithm

| JWS `alg` | Curve | Private / public key | Signature | Specification |
|-----------|-------|----------------------|-----------|---------------|
| EdDSA | Ed25519 (OKP) | 32 bytes each | 64 bytes | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) |

EdDSA is asymmetric: [`signing_key`](https://docs.rs/no-way-jose-eddsa/latest/no_way_jose_eddsa/fn.signing_key.html) generates a random signing key (OS randomness via `getrandom` with the `sys_rng` feature); [`verifying_key_from_signing`](https://docs.rs/no-way-jose-eddsa/latest/no_way_jose_eddsa/fn.verifying_key_from_signing.html) derives the public key. Keys can also be built from 32-byte seeds ([`signing_key_from_bytes`](https://docs.rs/no-way-jose-eddsa/latest/no_way_jose_eddsa/fn.signing_key_from_bytes.html)) or raw public bytes ([`verifying_key_from_bytes`](https://docs.rs/no-way-jose-eddsa/latest/no_way_jose_eddsa/fn.verifying_key_from_bytes.html)).

Uses [ed25519-dalek](https://docs.rs/ed25519-dalek) for Ed25519 signatures. `#![no_std]` compatible. Implements `JwkKeyConvert` for JWK import/export of OKP (Ed25519) keys.

## Example

```rust
use no_way_jose_core::json::RawJson;
use no_way_jose_core::validation::NoValidation;
use no_way_jose_core::{CompactJws, UnsignedToken};
use no_way_jose_eddsa::EdDsa;

let sk = no_way_jose_eddsa::signing_key();
let vk = no_way_jose_eddsa::verifying_key_from_signing(&sk);

let payload = r#"{"sub":"alice"}"#;
let claims = RawJson(payload.into());
let token_str = UnsignedToken::<EdDsa, _>::new(claims)
    .sign(&sk)
    .unwrap()
    .to_string();

let token: CompactJws<EdDsa> = token_str.parse().unwrap();
let verified = token
    .verify(&vk, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(verified.claims.0, payload);
```

See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

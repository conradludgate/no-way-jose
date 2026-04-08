# no-way-jose-rsa

RSA signing and content-key wrapping for JOSE: JWS with RSASSA-PKCS1-v1_5 / RSASSA-PSS, and JWE with RSAES-PKCS1-v1_5 / RSA-OAEP ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)).

Keys use the [`rsa`](https://docs.rs/rsa) crate’s `RsaPrivateKey` and `RsaPublicKey`. `#![no_std]` compatible.

## JWS algorithms

| JWS `alg` | Mechanism |
|-----------|-----------|
| RS256, RS384, RS512 | RSASSA-PKCS1-v1_5 (SHA-256 / SHA-384 / SHA-512) |
| PS256, PS384, PS512 | RSASSA-PSS with MGF1 (same hash) |

## JWE algorithms

| JWE `alg` | Mechanism |
|-----------|-----------|
| RSA1_5 | RSAES-PKCS1-v1_5 |
| RSA-OAEP | RSA-OAEP (SHA-1) |
| RSA-OAEP-256 | RSA-OAEP (SHA-256) |

Pair a key-management type (e.g. `RsaOaep`) with a content encryption implementation from another crate (e.g. `no-way-jose-aes-gcm`) as the `CE` parameter to [`CompactJwe`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJwe.html).

## JWS: sign and verify

```rust
use no_way_jose_core::json::RawJson;
use no_way_jose_core::validation::NoValidation;
use no_way_jose_core::{CompactJws, UnsignedToken};
use no_way_jose_rsa::{signing_key, verifying_key_from_signing, Rs256};

let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
let sk = signing_key(private);
let vk = verifying_key_from_signing(&sk);

let token_str = UnsignedToken::<Rs256, RawJson>::new(RawJson(r#"{"sub":"alice"}"#.into()))
    .sign(&sk)
    .unwrap()
    .to_string();

let token: CompactJws<Rs256, RawJson> = token_str.parse().unwrap();
let verified = token
    .verify(&vk, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(verified.claims.0, r#"{"sub":"alice"}"#);
```

## JWE: encrypt and decrypt

```rust
use no_way_jose_aes_gcm::A128Gcm;
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_rsa::{rsa_oaep, RsaOaep};

let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
let enc_key = rsa_oaep::key(private);

let compact = UnsealedToken::<Encrypted<RsaOaep, A128Gcm>, RawJson>::new(RawJson(
    r#"{"secret":"message"}"#.into(),
))
.encrypt(&enc_key)
.unwrap();
let token_str = compact.to_string();

let token: CompactJwe<RsaOaep, A128Gcm, RawJson> = token_str.parse().unwrap();
let unsealed = token
    .decrypt(&enc_key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"secret":"message"}"#);
```

## See also

- [no-way-jose-core](https://docs.rs/no-way-jose-core) — tokens, traits, JSON types
- [no-way-jose-claims](https://docs.rs/no-way-jose-claims) — registered JWT claims and validation

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

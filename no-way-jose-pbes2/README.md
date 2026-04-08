# no-way-jose-pbes2

PBES2 (password-based) key management for JWE: [`Pbes2Hs256A128Kw`](https://docs.rs/no-way-jose-pbes2/latest/no_way_jose_pbes2/struct.Pbes2Hs256A128Kw.html), [`Pbes2Hs384A192Kw`](https://docs.rs/no-way-jose-pbes2/latest/no_way_jose_pbes2/struct.Pbes2Hs384A192Kw.html), [`Pbes2Hs512A256Kw`](https://docs.rs/no-way-jose-pbes2/latest/no_way_jose_pbes2/struct.Pbes2Hs512A256Kw.html).

| Algorithm | PBKDF2 | Wrap KEK | RFC |
|-----------|--------|----------|-----|
| PBES2-HS256+A128KW | HMAC-SHA-256 | AES-128-KW | [RFC 7518 §4.8](https://www.rfc-editor.org/rfc/rfc7518#section-4.8) |
| PBES2-HS384+A192KW | HMAC-SHA-384 | AES-192-KW | [RFC 7518 §4.8](https://www.rfc-editor.org/rfc/rfc7518#section-4.8) |
| PBES2-HS512+A256KW | HMAC-SHA-512 | AES-256-KW | [RFC 7518 §4.8](https://www.rfc-editor.org/rfc/rfc7518#section-4.8) |

PBKDF2 derives a KEK from the password; a random CEK is wrapped and `p2s` / `p2c` are written to the protected header. Pair with a content algorithm such as [`A128Gcm`](https://docs.rs/no-way-jose-aes-gcm/latest/no_way_jose_aes_gcm/struct.A128Gcm.html).

`#![no_std]` compatible.

```rust
use no_way_jose_aes_gcm::A128Gcm;
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_pbes2::pbes2_hs256_a128kw;

let enc_key = pbes2_hs256_a128kw::key(b"correct-horse-battery-staple".to_vec());
let dec_key = pbes2_hs256_a128kw::key(b"correct-horse-battery-staple".to_vec());

let token =
    UnsealedToken::<Encrypted<no_way_jose_pbes2::Pbes2Hs256A128Kw, A128Gcm>, RawJson>::new(
        RawJson(r#"{"sub":"demo"}"#.into()),
    );
let compact = token.encrypt(&enc_key).unwrap();
let parsed: CompactJwe<no_way_jose_pbes2::Pbes2Hs256A128Kw, A128Gcm, RawJson> =
    compact.to_string().parse().unwrap();
let unsealed = parsed
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
```

See [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

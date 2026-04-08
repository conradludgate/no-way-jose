# no-way-jose-aes-gcm

AES-GCM content encryption for JWE ([`A128Gcm`](https://docs.rs/no-way-jose-aes-gcm/latest/no_way_jose_aes_gcm/struct.A128Gcm.html), [`A192Gcm`](https://docs.rs/no-way-jose-aes-gcm/latest/no_way_jose_aes_gcm/struct.A192Gcm.html), [`A256Gcm`](https://docs.rs/no-way-jose-aes-gcm/latest/no_way_jose_aes_gcm/struct.A256Gcm.html)).

| Algorithm | CEK size | IV | Tag | RFC |
|-----------|----------|----|-----|-----|
| A128GCM | 16 bytes | 12 bytes | 16 bytes | [RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3) |
| A192GCM | 24 bytes | 12 bytes | 16 bytes | [RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3) |
| A256GCM | 32 bytes | 12 bytes | 16 bytes | [RFC 7518 §5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3) |

These types implement [`ContentCipher`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/jwe_algorithm/trait.ContentCipher.html) from [no-way-jose-core](https://docs.rs/no-way-jose-core). Use them as the `CE` type parameter on [`CompactJwe`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJwe.html) together with a key-management algorithm (`dir`, AES-KW, ECDH-ES, etc.).

Uses the [RustCrypto](https://github.com/RustCrypto) `aes-gcm` crate. `#![no_std]` compatible.

```rust
use no_way_jose_aes_gcm::A256Gcm;
use no_way_jose_core::dir;
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;

let cek = vec![0u8; 32];
let enc_key = dir::key(cek.clone());
let dec_key = dir::key(cek);

let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, RawJson>::new(RawJson(
    r#"{"sub":"demo"}"#.into(),
));
let compact = token.encrypt(&enc_key).unwrap();
let parsed: CompactJwe<dir::Dir, A256Gcm, RawJson> = compact.to_string().parse().unwrap();
let unsealed = parsed
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
```

See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

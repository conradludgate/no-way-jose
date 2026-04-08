# no-way-jose-aes-kw

AES Key Wrap (RFC 3394) for JWE: [`A128Kw`](https://docs.rs/no-way-jose-aes-kw/latest/no_way_jose_aes_kw/struct.A128Kw.html), [`A192Kw`](https://docs.rs/no-way-jose-aes-kw/latest/no_way_jose_aes_kw/struct.A192Kw.html), [`A256Kw`](https://docs.rs/no-way-jose-aes-kw/latest/no_way_jose_aes_kw/struct.A256Kw.html).

| Algorithm | KEK size | RFC |
|-----------|----------|-----|
| A128KW | 16 bytes | [RFC 7518 §4.4](https://www.rfc-editor.org/rfc/rfc7518#section-4.4) |
| A192KW | 24 bytes | [RFC 7518 §4.4](https://www.rfc-editor.org/rfc/rfc7518#section-4.4) |
| A256KW | 32 bytes | [RFC 7518 §4.4](https://www.rfc-editor.org/rfc/rfc7518#section-4.4) |

A random CEK is wrapped with the KEK and carried in the JWE `encrypted_key` field. Pair with a content-encryption type (for example [`A128Gcm`](https://docs.rs/no-way-jose-aes-gcm/latest/no_way_jose_aes_gcm/struct.A128Gcm.html)) as the `CE` parameter on [`CompactJwe`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJwe.html).

`#![no_std]` compatible.

```rust
use no_way_jose_aes_gcm::A128Gcm;
use no_way_jose_aes_kw::a128kw;
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;

let kek = vec![0x42u8; 16];
let enc_key = a128kw::key(kek.clone()).unwrap();
let dec_key = a128kw::key(kek).unwrap();

let token = UnsealedToken::<Encrypted<no_way_jose_aes_kw::A128Kw, A128Gcm>, RawJson>::new(
    RawJson(r#"{"sub":"demo"}"#.into()),
);
let compact = token.encrypt(&enc_key).unwrap();
let parsed: CompactJwe<no_way_jose_aes_kw::A128Kw, A128Gcm, RawJson> =
    compact.to_string().parse().unwrap();
let unsealed = parsed
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
```

Use the `a128kw`, `a192kw`, or `a256kw` modules to build keys. See [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

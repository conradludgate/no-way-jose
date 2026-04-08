# no-way-jose-aes-gcm-kw

AES-GCM key wrapping for JWE: [`A128GcmKw`](https://docs.rs/no-way-jose-aes-gcm-kw/latest/no_way_jose_aes_gcm_kw/struct.A128GcmKw.html), [`A192GcmKw`](https://docs.rs/no-way-jose-aes-gcm-kw/latest/no_way_jose_aes_gcm_kw/struct.A192GcmKw.html), [`A256GcmKw`](https://docs.rs/no-way-jose-aes-gcm-kw/latest/no_way_jose_aes_gcm_kw/struct.A256GcmKw.html).

| Algorithm | KEK size | Header params | RFC |
|-----------|----------|---------------|-----|
| A128GCMKW | 16 bytes | `iv`, `tag` (base64url JSON strings) | [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518#section-4.7) |
| A192GCMKW | 24 bytes | same | [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518#section-4.7) |
| A256GCMKW | 32 bytes | same | [RFC 7518 §4.7](https://www.rfc-editor.org/rfc/rfc7518#section-4.7) |

The KEK encrypts a random CEK with AES-GCM; wrapping `iv` and `tag` are placed in the protected header. Combine with a content algorithm such as [`A128Gcm`](https://docs.rs/no-way-jose-aes-gcm/latest/no_way_jose_aes_gcm/struct.A128Gcm.html) on [`CompactJwe`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJwe.html).

`#![no_std]` compatible.

```rust
use no_way_jose_aes_gcm::A128Gcm;
use no_way_jose_aes_gcm_kw::a128gcmkw;
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;

let kek = vec![0x42u8; 16];
let enc_key = a128gcmkw::key(kek.clone()).unwrap();
let dec_key = a128gcmkw::key(kek).unwrap();

let token =
    UnsealedToken::<Encrypted<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm>, RawJson>::new(
        RawJson(r#"{"sub":"demo"}"#.into()),
    );
let compact = token.encrypt(&enc_key).unwrap();
let parsed: CompactJwe<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm, RawJson> =
    compact.to_string().parse().unwrap();
let unsealed = parsed
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
```

See [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

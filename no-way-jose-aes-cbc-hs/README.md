# no-way-jose-aes-cbc-hs

AES-CBC with HMAC-SHA (encrypt-then-MAC) for JWE: [`A128CbcHs256`](https://docs.rs/no-way-jose-aes-cbc-hs/latest/no_way_jose_aes_cbc_hs/struct.A128CbcHs256.html), [`A192CbcHs384`](https://docs.rs/no-way-jose-aes-cbc-hs/latest/no_way_jose_aes_cbc_hs/struct.A192CbcHs384.html), [`A256CbcHs512`](https://docs.rs/no-way-jose-aes-cbc-hs/latest/no_way_jose_aes_cbc_hs/struct.A256CbcHs512.html).

| Algorithm | CEK size | IV | Tag | RFC |
|-----------|----------|----|-----|-----|
| A128CBC-HS256 | 32 bytes (16 MAC + 16 AES) | 16 bytes | 16 bytes | [RFC 7518 §5.2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2) |
| A192CBC-HS384 | 48 bytes (24 + 24) | 16 bytes | 24 bytes | [RFC 7518 §5.2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2) |
| A256CBC-HS512 | 64 bytes (32 + 32) | 16 bytes | 32 bytes | [RFC 7518 §5.2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2) |

These types implement [`ContentCipher`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/jwe_algorithm/trait.ContentCipher.html) from [no-way-jose-core](https://docs.rs/no-way-jose-core). Use them as the `CE` parameter on [`CompactJwe`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJwe.html) with your chosen key-management algorithm.

`#![no_std]` compatible.

```rust
use no_way_jose_aes_cbc_hs::A128CbcHs256;
use no_way_jose_core::dir;
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;

let cek = vec![0u8; 32];
let enc_key = dir::key(cek.clone());
let dec_key = dir::key(cek);

let token = UnsealedToken::<Encrypted<dir::Dir, A128CbcHs256>, RawJson>::new(RawJson(
    r#"{"sub":"demo"}"#.into(),
));
let compact = token.encrypt(&enc_key).unwrap();
let parsed: CompactJwe<dir::Dir, A128CbcHs256, RawJson> =
    compact.to_string().parse().unwrap();
let unsealed = parsed
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
```

See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

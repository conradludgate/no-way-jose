# no-way-jose-ecdh-es

ECDH-ES and ECDH-ES + AES Key Wrap for JWE: [`EcdhEs`](https://docs.rs/no-way-jose-ecdh-es/latest/no_way_jose_ecdh_es/struct.EcdhEs.html), [`EcdhEsA128Kw`](https://docs.rs/no-way-jose-ecdh-es/latest/no_way_jose_ecdh_es/struct.EcdhEsA128Kw.html), [`EcdhEsA192Kw`](https://docs.rs/no-way-jose-ecdh-es/latest/no_way_jose_ecdh_es/struct.EcdhEsA192Kw.html), [`EcdhEsA256Kw`](https://docs.rs/no-way-jose-ecdh-es/latest/no_way_jose_ecdh_es/struct.EcdhEsA256Kw.html).

| Algorithm | Derived key | CEK handling | RFC |
|-----------|-------------|--------------|-----|
| ECDH-ES | Concat KDF → CEK length | CEK = derived key | [RFC 7518 §4.6](https://www.rfc-editor.org/rfc/rfc7518#section-4.6) |
| ECDH-ES+A128KW | Concat KDF → 16 bytes | AES-KW wrap | [RFC 7518 §4.6](https://www.rfc-editor.org/rfc/rfc7518#section-4.6) |
| ECDH-ES+A192KW | Concat KDF → 24 bytes | AES-KW wrap | [RFC 7518 §4.6](https://www.rfc-editor.org/rfc/rfc7518#section-4.6) |
| ECDH-ES+A256KW | Concat KDF → 32 bytes | AES-KW wrap | [RFC 7518 §4.6](https://www.rfc-editor.org/rfc/rfc7518#section-4.6) |

Curves: P-256, P-384 ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)), X25519 ([RFC 8037](https://www.rfc-editor.org/rfc/rfc8037)). Each encrypt builds an ephemeral key pair; the ephemeral public key is sent as `epk` in the protected header. [`EncryptionKey`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.EncryptionKey.html) holds the recipient's long-term private key ([`EcPrivateKey`](https://docs.rs/no-way-jose-ecdh-es/latest/no_way_jose_ecdh_es/enum.EcPrivateKey.html)).

`#![no_std]` compatible.

```rust
use no_way_jose_aes_gcm::A128Gcm;
use no_way_jose_ecdh_es::{ecdh_es_a128kw, EcPrivateKey};
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use p256::elliptic_curve::Generate;

let secret = p256::SecretKey::generate_from_rng(&mut getrandom::rand_core::UnwrapErr(
    getrandom::SysRng,
));
let key = ecdh_es_a128kw::key(EcPrivateKey::P256(secret));

let token = UnsealedToken::<Encrypted<no_way_jose_ecdh_es::EcdhEsA128Kw, A128Gcm>, RawJson>::new(
    RawJson(r#"{"sub":"demo"}"#.into()),
);
let compact = token.encrypt(&key).unwrap();
let parsed: CompactJwe<no_way_jose_ecdh_es::EcdhEsA128Kw, A128Gcm, RawJson> =
    compact.to_string().parse().unwrap();
let unsealed = parsed
    .decrypt(&key, &NoValidation::dangerous_no_validation())
    .unwrap();
assert_eq!(unsealed.claims.0, r#"{"sub":"demo"}"#);
```

See [no-way-jose-core](https://docs.rs/no-way-jose-core) and [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

Repository: [no-way-jose](https://github.com/conradludgate/no-way-jose).

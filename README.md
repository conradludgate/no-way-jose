# no-way-jose

A type-safe Rust implementation of the JOSE (JSON Object Signing and Encryption) standards.

Algorithms are selected at the type level, so the compiler prevents key/algorithm
mismatches before your code ever runs. The core crate is `no_std`-compatible and has
no dependency on `serde`.

## What is JOSE?

JOSE is a family of IETF standards for securing data with JSON-based structures:

- **JWT** (JSON Web Token, [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) --
  A compact, URL-safe format for transferring claims between two parties. A JWT is
  either *signed* (JWS) or *encrypted* (JWE).

- **JWS** (JSON Web Signature, [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) --
  A signed token in three base64url-encoded parts: `header.payload.signature`.
  The signature proves the payload has not been tampered with and was created by
  the holder of a secret or private key.

- **JWE** (JSON Web Encryption, [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)) --
  An encrypted token in five base64url-encoded parts:
  `header.encrypted_key.iv.ciphertext.tag`. The payload is confidential --
  only the holder of the decryption key can read it.

- **JWA** (JSON Web Algorithms, [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)) --
  The registry of cryptographic algorithms used by JWS and JWE.

- **JWK** (JSON Web Key, [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) --
  A JSON format for representing cryptographic keys. Keys can be serialized
  to/from JWK for interoperability with other JOSE libraries and key stores.

JWTs are widely used for authentication tokens, API authorization, and
inter-service communication.

## Design goals

- **Compile-time algorithm safety.** Algorithms are zero-sized types (e.g. `Hs256`,
  `Es256`, `A256Gcm`). A `CompactJws<Hs256>` can only be verified with a
  `VerifyingKey<Hs256>` -- passing an `Es256` key is a compile error.

- **Modular crate structure.** Pick only the algorithms you need. Each algorithm
  family lives in its own crate with only the necessary crypto dependency.

- **No serde in core.** `no-way-jose-core` uses a built-in minimal JSON reader/writer
  with strict compact-JSON parsing (no whitespace). Claim types implement `ToJson`
  and `FromJson` directly.

- **Sealed traits.** Algorithm traits are sealed -- users cannot create custom
  algorithm types that could weaken security guarantees.

- **Structured errors.** All operations return `Report<JoseError>` via
  [`error-stack`](https://docs.rs/error-stack). Errors carry context chains
  (e.g. `Base64Decode`, `MalformedToken`, `CryptoError`) without exposing
  internal dependency types, preserving semver stability.

- **`no_std`-ready.** The core crate and all algorithm crates use `#![no_std]`
  with `alloc`.

## Quick start

Sign and verify a JWT with HMAC-SHA256:

```rust
use no_way_jose_claims::{RegisteredClaims, Time, HasExpiry, ForAudience, Validate};
use no_way_jose_claims::jiff::SignedDuration;
use no_way_jose_core::CompactJws;
use no_way_jose_hmac::Hs256;

// Create a signing key (HMAC uses the same secret for signing and verifying)
let secret = b"my-secret-key-at-least-32-bytes!".to_vec();
let signing_key = no_way_jose_hmac::symmetric_key(secret.clone()).unwrap();
let verifying_key = no_way_jose_hmac::verifying_key(secret).unwrap();

// Build claims with a 1-hour expiry
let claims = RegisteredClaims::new(
        no_way_jose_claims::jiff::Timestamp::now(),
        SignedDuration::from_hours(1),
    )
    .unwrap()
    .from_issuer("my-service")
    .for_audience("my-app");

// Sign
let token_string = no_way_jose_core::UnsignedToken::<Hs256, _>::new(claims)
    .sign(&signing_key)
    .unwrap()
    .to_string();

// Verify
let token: CompactJws<Hs256, RegisteredClaims> = token_string.parse().unwrap();
let verified = token
    .verify(
        &verifying_key,
        &HasExpiry
            .and_then(Time::valid_now())
            .and_then(ForAudience("my-app")),
    )
    .unwrap();

assert_eq!(verified.claims.iss.as_deref(), Some("my-service"));
```

## Crate map

```
no-way-jose/
  no-way-jose-core/       Core traits, token types, base64url, dir key mgmt
  no-way-jose-claims/     RegisteredClaims and JWT validators
  no-way-jose-hmac/       HS256, HS384, HS512 (HMAC)
  no-way-jose-ecdsa/      ES256, ES384, ES512 (ECDSA)
  no-way-jose-eddsa/      EdDSA Ed25519
  no-way-jose-rsa/        RS256, RS384, RS512, PS256, PS384, PS512 (JWS), RSA1_5, RSA-OAEP, RSA-OAEP-256 (JWE)
  no-way-jose-aes-gcm/    A128GCM, A192GCM, A256GCM (JWE content encryption)
  no-way-jose-aes-cbc-hs/ A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (JWE CE)
  no-way-jose-aes-kw/     A128KW, A192KW, A256KW (JWE key wrapping)
  no-way-jose-aes-gcm-kw/ A128GCMKW, A192GCMKW, A256GCMKW (JWE key wrapping)
  no-way-jose-ecdh-es/    ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW (P-256/P-384/X25519)
  no-way-jose-pbes2/      PBES2-HS256+A128KW, HS384+A192KW, HS512+A256KW (JWE)
  no-way-jose-graviola/   Alternate crypto backend (graviola)
```

All crates except `no-way-jose-claims` are `#![no_std]` with `extern crate alloc`.

## How-to guides

### Sign and verify with asymmetric keys (ES256)

```rust
use no_way_jose_core::{CompactJws, UnsignedToken};
use no_way_jose_core::json::{ToJson, FromJson, JsonWriter, JsonReader};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_ecdsa::Es256;

// Generate or load a P-256 private key (here from raw scalar bytes)
let sk = no_way_jose_ecdsa::signing_key_from_bytes(&private_key_bytes).unwrap();
let vk = no_way_jose_ecdsa::verifying_key_from_signing(&sk);

let token_string = UnsignedToken::<Es256, _>::new(my_claims)
    .sign(&sk)
    .unwrap()
    .to_string();

let token: CompactJws<Es256, MyClaims> = token_string.parse().unwrap();
let verified = token
    .verify(&vk, &NoValidation::dangerous_no_validation())
    .unwrap();
```

### Encrypt and decrypt a JWE (direct key)

With `dir`, a shared symmetric key is used directly as the Content Encryption Key.

```rust
use no_way_jose_core::dir;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_aes_gcm::A256Gcm;

let key_bytes = vec![/* 32 bytes of shared secret */];
let enc_key = dir::encryption_key(key_bytes.clone());
let dec_key = dir::decryption_key(key_bytes);

// Encrypt
let compact = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, MyClaims>::new(claims)
    .encrypt(&enc_key)
    .unwrap();

let token_string = compact.to_string();  // 5-part compact serialization

// Decrypt
let token: CompactJwe<dir::Dir, A256Gcm, MyClaims> = token_string.parse().unwrap();
let unsealed = token
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
```

### Encrypt with key wrapping (A128KW + A128GCM)

With AES Key Wrap, a Key Encryption Key (KEK) wraps a randomly generated Content
Encryption Key that is transmitted in the token.

```rust
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_aes_gcm::A128Gcm;
use no_way_jose_aes_kw::A128Kw;

let kek = vec![/* 16 bytes */];
let enc_key = no_way_jose_aes_kw::a128kw::encryption_key(kek.clone()).unwrap();
let dec_key = no_way_jose_aes_kw::a128kw::decryption_key(kek).unwrap();

let compact = UnsealedToken::<Encrypted<A128Kw, A128Gcm>, MyClaims>::new(claims)
    .encrypt(&enc_key)
    .unwrap();

let token: CompactJwe<A128Kw, A128Gcm, MyClaims> = compact.to_string().parse().unwrap();
let unsealed = token
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();
```

### Build tokens with custom headers

Use the builder to set optional header fields like `kid` and `typ`:

```rust
use no_way_jose_core::UnsignedToken;
use no_way_jose_hmac::Hs256;

let token_string = UnsignedToken::<Hs256, _>::builder(my_claims)
    .kid("my-key-id")
    .typ("JWT")
    .build()
    .sign(&signing_key)
    .unwrap()
    .to_string();
```

### Create a nested JWT (sign then encrypt)

A nested JWT signs a token first, then encrypts the compact JWS as the payload
of a JWE. The outer header uses `"cty": "JWT"` to signal that the plaintext is
itself a JWT ([RFC 7519 §5.2](https://datatracker.ietf.org/doc/html/rfc7519#section-5.2)).

```rust
use no_way_jose_core::json::RawJson;
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_hmac::Hs256;
use no_way_jose_aes_gcm::A256Gcm;
use no_way_jose_core::dir;

// 1. Sign the inner token
let inner_compact = no_way_jose_core::UnsignedToken::<Hs256, _>::new(my_claims)
    .sign(&signing_key)
    .unwrap()
    .to_string();

// 2. Encrypt with cty: "JWT"
let encrypted = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, RawJson>::builder(
        RawJson(inner_compact.into_bytes()),
    )
    .cty("JWT")
    .build()
    .encrypt(&enc_key)
    .unwrap()
    .to_string();

// 3. Decrypt, check cty, then verify the inner JWS
let outer: CompactJwe<dir::Dir, A256Gcm> = encrypted.parse().unwrap();
let outer = outer.require_cty("JWT").unwrap();
let decrypted = outer
    .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
    .unwrap();

let inner_str = core::str::from_utf8(&decrypted.claims.0).unwrap();
let inner: no_way_jose_core::CompactJws<Hs256, MyClaims> = inner_str.parse().unwrap();
let verified = inner.verify(&verifying_key, &validator).unwrap();
```

### Custom claims with `ToJson` / `FromJson`

Implement `ToJson` and `FromJson` for your own claim types:

```rust
use no_way_jose_core::json::{ToJson, FromJson, JsonWriter, JsonReader};

struct MyClaims {
    sub: String,
    admin: bool,
}

impl ToJson for MyClaims {
    fn write_json(&self, buf: &mut Vec<u8>) {
        let mut w = JsonWriter::new();
        w.string("sub", &self.sub);
        w.bool("admin", self.admin);
        buf.extend_from_slice(&w.finish());
    }
}

impl FromJson for MyClaims {
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = JsonReader::new(bytes)?;
        let mut sub = None;
        let mut admin = None;
        while let Some(key) = reader.next_key()? {
            match key {
                "sub" => sub = Some(reader.read_string()?),
                "admin" => admin = Some(reader.read_bool()?),
                _ => reader.skip_value()?,
            }
        }
        Ok(MyClaims {
            sub: sub.ok_or("missing sub")?,
            admin: admin.ok_or("missing admin")?,
        })
    }
}
```

If you don't need to parse the payload, use `RawJson` -- it stores the raw bytes
without any deserialization.

### Validate claims

Validators implement the `Validate` trait and compose with `and_then`:

```rust
use no_way_jose_claims::{HasExpiry, Time, FromIssuer, ForAudience, Validate};

let validator = HasExpiry
    .and_then(Time::valid_now())
    .and_then(FromIssuer("auth.example.com"))
    .and_then(ForAudience("my-api"));

// Pass the validator to verify() or decrypt()
let verified = token.verify(&key, &validator).unwrap();
```

You can also implement `Validate` for your own claim type to add custom rules.

### Work with JWK keys

Export a key to JWK JSON and import it back:

```rust
use no_way_jose_core::jwk::{Jwk, ToJwk, FromJwk};

let sk = no_way_jose_ecdsa::signing_key_from_bytes(&key_bytes).unwrap();

// Export to JWK JSON
let jwk: Jwk = sk.to_jwk();
let jwk_json: String = jwk.to_json();

// Import from JWK JSON
let jwk = Jwk::from_json(jwk_json.as_bytes()).unwrap();
let vk: no_way_jose_ecdsa::VerifyingKey = FromJwk::from_jwk(&jwk).unwrap();
```

### Verify a token using a JWK Set

Parse an incoming token, read its `kid` header, look up the matching key in a
JWK Set, and verify:

```rust
use no_way_jose_core::UntypedCompactJws;
use no_way_jose_core::jwk::{JwkSet, FromJwk};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_claims::RegisteredClaims;

// Parse a JWK Set (e.g. fetched from a /.well-known/jwks.json endpoint)
let jwks = JwkSet::from_json(&jwks_json).unwrap();

// Parse the token without knowing the algorithm yet
let untyped: UntypedCompactJws<RegisteredClaims> = token_string.parse().unwrap();

// Read the kid from the token header and find the matching JWK
let header = untyped.header().unwrap();
let kid = header.kid.as_deref().expect("token has no kid");
let jwk = jwks.find_by_kid(kid).expect("unknown kid");

// Dispatch on the algorithm and verify
match untyped.alg() {
    "RS256" => {
        let vk = FromJwk::from_jwk(jwk).unwrap();
        let typed = untyped.into_typed::<no_way_jose_rsa::Rs256>().unwrap();
        let verified = typed.verify(&vk, &validator).unwrap();
    }
    "ES256" => {
        let vk = FromJwk::from_jwk(jwk).unwrap();
        let typed = untyped.into_typed::<no_way_jose_ecdsa::Es256>().unwrap();
        let verified = typed.verify(&vk, &validator).unwrap();
    }
    alg => panic!("unsupported algorithm: {alg}"),
}
```

### Compute a JWK Thumbprint

A JWK Thumbprint (RFC 7638) is a hash of the key's canonical JSON form, useful
as a stable key identifier:

```rust
use sha2::{Sha256, Digest};
use no_way_jose_core::jwk::Jwk;

let jwk = Jwk::from_json(&jwk_json).unwrap();
let canonical = jwk.thumbprint_canonical_json();
let thumbprint = Sha256::digest(&canonical);
let thumbprint_b64 = no_way_jose_core::base64url::encode(&thumbprint);
```

## Supported algorithms

### JWS (signing)

| Algorithm | Type | Crate | RFC |
|-----------|------|-------|-----|
| HS256 | HMAC-SHA256 | `no-way-jose-hmac` | 7518 §3.2 |
| HS384 | HMAC-SHA384 | `no-way-jose-hmac` | 7518 §3.2 |
| HS512 | HMAC-SHA512 | `no-way-jose-hmac` | 7518 §3.2 |
| ES256 | ECDSA P-256 | `no-way-jose-ecdsa` | 7518 §3.4 |
| ES384 | ECDSA P-384 | `no-way-jose-ecdsa` | 7518 §3.4 |
| EdDSA | Ed25519 | `no-way-jose-eddsa` | 8037 |
| RS256 | RSASSA-PKCS1-v1_5 | `no-way-jose-rsa` | 7518 §3.3 |
| PS256 | RSASSA-PSS SHA-256 | `no-way-jose-rsa` | 7518 §3.5 |
| RS384 | RSASSA-PKCS1-v1_5 SHA-384 | `no-way-jose-rsa` | 7518 §3.3 |
| RS512 | RSASSA-PKCS1-v1_5 SHA-512 | `no-way-jose-rsa` | 7518 §3.3 |
| PS384 | RSASSA-PSS SHA-384 | `no-way-jose-rsa` | 7518 §3.5 |
| PS512 | RSASSA-PSS SHA-512 | `no-way-jose-rsa` | 7518 §3.5 |
| ES512 | ECDSA P-521 | `no-way-jose-ecdsa` | 7518 §3.4 |

### JWE key management

| Algorithm | Type | Crate | RFC |
|-----------|------|-------|-----|
| dir | Direct key | `no-way-jose-core` | 7518 §4.5 |
| A128KW | AES-128 Key Wrap | `no-way-jose-aes-kw` | 7518 §4.4 |
| A192KW | AES-192 Key Wrap | `no-way-jose-aes-kw` | 7518 §4.4 |
| A256KW | AES-256 Key Wrap | `no-way-jose-aes-kw` | 7518 §4.4 |
| A128GCMKW | AES-128-GCM Key Wrap | `no-way-jose-aes-gcm-kw` | 7518 §4.7 |
| A192GCMKW | AES-192-GCM Key Wrap | `no-way-jose-aes-gcm-kw` | 7518 §4.7 |
| A256GCMKW | AES-256-GCM Key Wrap | `no-way-jose-aes-gcm-kw` | 7518 §4.7 |
| RSA1_5 | RSA PKCS#1 v1.5 | `no-way-jose-rsa` | 7518 §4.2 |
| RSA-OAEP | RSA-OAEP SHA-1 | `no-way-jose-rsa` | 7518 §4.3 |
| RSA-OAEP-256 | RSA-OAEP SHA-256 | `no-way-jose-rsa` | 7518 §4.3 |
| ECDH-ES | ECDH-ES direct (P-256/P-384/X25519) | `no-way-jose-ecdh-es` | 7518 §4.6 |
| ECDH-ES+A128KW | ECDH-ES + AES-128 Wrap | `no-way-jose-ecdh-es` | 7518 §4.6 |
| ECDH-ES+A192KW | ECDH-ES + AES-192 Wrap | `no-way-jose-ecdh-es` | 7518 §4.6 |
| ECDH-ES+A256KW | ECDH-ES + AES-256 Wrap | `no-way-jose-ecdh-es` | 7518 §4.6 |
| PBES2-HS256+A128KW | PBES2 + AES-128 Wrap | `no-way-jose-pbes2` | 7518 §4.8 |
| PBES2-HS384+A192KW | PBES2 + AES-192 Wrap | `no-way-jose-pbes2` | 7518 §4.8 |
| PBES2-HS512+A256KW | PBES2 + AES-256 Wrap | `no-way-jose-pbes2` | 7518 §4.8 |

### JWE content encryption

| Algorithm | Type | Crate | RFC |
|-----------|------|-------|-----|
| A128GCM | AES-128-GCM | `no-way-jose-aes-gcm` | 7518 §5.3 |
| A192GCM | AES-192-GCM | `no-way-jose-aes-gcm` | 7518 §5.3 |
| A256GCM | AES-256-GCM | `no-way-jose-aes-gcm` | 7518 §5.3 |
| A128CBC-HS256 | AES-128-CBC + HMAC-SHA-256 | `no-way-jose-aes-cbc-hs` | 7518 §5.2 |
| A192CBC-HS384 | AES-192-CBC + HMAC-SHA-384 | `no-way-jose-aes-cbc-hs` | 7518 §5.2 |
| A256CBC-HS512 | AES-256-CBC + HMAC-SHA-512 | `no-way-jose-aes-cbc-hs` | 7518 §5.2 |

### Alternate crypto backend (graviola)

`no-way-jose-graviola` provides the same JWS algorithms (ES256, ES384, EdDSA,
HS256/384/512, RS256, PS256) and AES-GCM content encryption (A128GCM, A256GCM)
using the [graviola](https://crates.io/crates/graviola) library -- a crypto
library with formally verified assembler. Tokens produced by either backend are
interchangeable on the wire.

Graviola is limited to aarch64 and x86\_64 with specific CPU features.

## Limitations

- **Compact serialization only.** JWS/JWE JSON Serialization (RFC 7515 §7.2,
  RFC 7516 §7.2) is not supported. The only significant protocol using it is
  ACME (RFC 8555). All standard JWT/OAuth/OIDC flows use compact serialization.

## Security considerations

- **Algorithm type safety.** The wrong key type for a token is a compile error,
  preventing algorithm confusion attacks.
- **`crit` header rejection.** Tokens with a `crit` header parameter are rejected
  unless explicitly handled ([RFC 7515 §4.1.11](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11)).
- **`require_typ` validation.** Enforce the `typ` header to prevent token
  substitution across different applications
  ([RFC 8725 §3.11](https://datatracker.ietf.org/doc/html/rfc8725#section-3.11)).
- **`require_cty` validation.** Enforce the `cty` header to verify that a
  token contains a nested JWT
  ([RFC 7519 §5.2](https://datatracker.ietf.org/doc/html/rfc7519#section-5.2)).
- **Minimum key lengths.** HMAC keys shorter than the hash output are rejected
  (32 bytes for HS256, 48 for HS384, 64 for HS512).
- **Sealed traits.** Algorithm traits cannot be implemented outside this workspace,
  preventing injection of weak custom algorithms.
- **Strict JSON parsing.** The JSON parser rejects whitespace between tokens,
  enforcing compact serialization.

## Status and roadmap

See [DESIGN.md](DESIGN.md) for the full implementation status, RFC coverage, and
future plans (more algorithms, alternate backends, etc).

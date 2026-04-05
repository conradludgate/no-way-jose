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

- **`no_std`-ready.** The core crate and several algorithm crates use `#![no_std]`
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
  no-way-jose-core/     Core traits, token types, base64url, Dir key mgmt (no_std)
  no-way-jose-claims/   RegisteredClaims and JWT validators
  no-way-jose-ecdsa/    ES256, ES384 (ECDSA)
  no-way-jose-eddsa/    EdDSA Ed25519
  no-way-jose-hmac/     HS256, HS384, HS512 (HMAC)
  no-way-jose-rsa/      RS256 (RSA PKCS#1 v1.5)
  no-way-jose-aes-gcm/  A128GCM, A256GCM (JWE content encryption)
  no-way-jose-aes-kw/   A128KW, A192KW, A256KW (JWE key wrapping)
```

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

### Dynamic algorithm dispatch

When the algorithm is not known at compile time (e.g. reading tokens from
multiple issuers), parse into `UntypedCompactJws` first:

```rust
use no_way_jose_core::UntypedCompactJws;

let untyped: UntypedCompactJws<MyClaims> = token_string.parse().unwrap();

match untyped.alg() {
    "HS256" => {
        let typed = untyped.into_typed::<no_way_jose_hmac::Hs256>().unwrap();
        typed.verify(&hmac_key, &validator).unwrap();
    }
    "ES256" => {
        let typed = untyped.into_typed::<no_way_jose_ecdsa::Es256>().unwrap();
        typed.verify(&ecdsa_key, &validator).unwrap();
    }
    alg => panic!("unsupported algorithm: {alg}"),
}
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

### JWE key management

| Algorithm | Type | Crate | RFC |
|-----------|------|-------|-----|
| dir | Direct key | `no-way-jose-core` | 7518 §4.5 |
| A128KW | AES-128 Key Wrap | `no-way-jose-aes-kw` | 7518 §4.4 |
| A192KW | AES-192 Key Wrap | `no-way-jose-aes-kw` | 7518 §4.4 |
| A256KW | AES-256 Key Wrap | `no-way-jose-aes-kw` | 7518 §4.4 |

### JWE content encryption

| Algorithm | Type | Crate | RFC |
|-----------|------|-------|-----|
| A128GCM | AES-128-GCM | `no-way-jose-aes-gcm` | 7518 §5.3 |
| A256GCM | AES-256-GCM | `no-way-jose-aes-gcm` | 7518 §5.3 |

## Security considerations

- **Algorithm type safety.** The wrong key type for a token is a compile error,
  preventing algorithm confusion attacks.
- **`crit` header rejection.** Tokens with a `crit` header parameter are rejected
  unless explicitly handled ([RFC 7515 §4.1.11](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11)).
- **`require_typ` validation.** Enforce the `typ` header to prevent token
  substitution across different applications
  ([RFC 8725 §3.11](https://datatracker.ietf.org/doc/html/rfc8725#section-3.11)).
- **Minimum key lengths.** HMAC keys shorter than the hash output are rejected
  (32 bytes for HS256, 48 for HS384, 64 for HS512).
- **Sealed traits.** Algorithm traits cannot be implemented outside this workspace,
  preventing injection of weak custom algorithms.
- **Strict JSON parsing.** The JSON parser rejects whitespace between tokens,
  enforcing compact serialization.

## Status and roadmap

See [DESIGN.md](DESIGN.md) for the full implementation status, RFC coverage, and
future plans (more algorithms, JWK support, serde integration, etc).

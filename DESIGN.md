# no-way-jose — Design Document

A type-safe Rust JOSE (JWS/JWE/JWT/JWK) library inspired by the
[paseto](https://github.com/conradludgate/paseto) crate's architecture.

## RFC References

| RFC  | Title                                              | Status      |
|------|----------------------------------------------------|-------------|
| 7515 | JSON Web Signature (JWS)                           | Done        |
| 7516 | JSON Web Encryption (JWE)                          | Done        |
| 7517 | JSON Web Key (JWK)                                 | Planned     |
| 7518 | JSON Web Algorithms (JWA)                          | Done        |
| 7519 | JSON Web Token (JWT)                               | Done        |
| 7520 | Examples of Protecting Content Using JOSE           | Test vectors|
| 7638 | JSON Web Key (JWK) Thumbprint                      | Planned     |
| 8037 | CFRG Elliptic Curve Diffie-Hellman and Signatures  | Done (EdDSA)|
| 8725 | JSON Web Token Best Current Practices              | Partial     |

## Crate Map

```
no-way-jose/
  no-way-jose-core/        Core traits, token types, Dir key mgmt, base64url (no_std, no crypto deps)
  no-way-jose-claims/      Registered JWT claims and validators
  no-way-jose-aes-cbc-hs/  A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 (JWE content encryption)
  no-way-jose-aes-gcm/     A128GCM, A256GCM (JWE content encryption)
  no-way-jose-aes-gcm-kw/  A128GCMKW, A192GCMKW, A256GCMKW (JWE key wrapping + header params)
  no-way-jose-aes-kw/      A128KW, A192KW, A256KW (JWE key wrapping)
  no-way-jose-ecdh-es/     ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW (JWE key agreement + header params)
  no-way-jose-ecdsa/       ES256, ES384 (ECDSA JWS)
  no-way-jose-eddsa/       EdDSA Ed25519 (JWS)
  no-way-jose-hmac/        HS256, HS384, HS512 (HMAC JWS)
  no-way-jose-pbes2/       PBES2-HS256+A128KW, HS384+A192KW, HS512+A256KW (password-based JWE + header params)
  no-way-jose-rsa/         RS256 (JWS), RSA1_5, RSA-OAEP, RSA-OAEP-256 (JWE key management)
  no-way-jose-test/        Integration tests (unpublished)
```

## Architecture Overview

### Type-level safety

Algorithms are zero-sized type markers (e.g. `Es256`, `Hs256`). Tokens carry
the algorithm as a type parameter so the compiler enforces correct key usage:

```
CompactToken<Signed<Es256>, M>  can only be verified with  VerifyingKey<Es256>
CompactToken<Signed<Hs256>, M>  can only be verified with  VerifyingKey<Hs256>
```

### Trait hierarchy

```
JwsAlgorithm          Algorithm marker (ALG constant)
  └─ sealed

Purpose               Wire-format discriminant (Signed / Encrypted)
  ├─ Signed<A>        3-part compact: header.payload.signature
  └─ Encrypted<KM,CE> 5-part compact: header.ek.iv.ct.tag

HasKey<K>             Maps algorithm → concrete key type
Signer / Verifier     Crypto entry points (impl by algorithm crates)
Payload               Encode/decode token body
Validate              Claims validation (composable)
```

### Token lifecycle

```
UnsealedToken::new(claims)
  │
  ├── .sign(key)      ──►  CompactToken<Signed<A>, M>       ──►  Display  ──►  wire
  │                                                                  │
  │                         FromStr  ◄──  wire  ◄────────────────────┘
  │                            │
  ├── ◄── .verify(key, v) ────┘
  │
  ├── .encrypt(key)   ──►  CompactToken<Encrypted<KM,CE>, M>  ──►  Display  ──►  wire
  │                                                                     │
  │                         FromStr  ◄──  wire  ◄───────────────────────┘
  │                            │
  └── ◄── .decrypt(key, v) ───┘
```

### JSON handling

`no-way-jose-core` has no dependency on `serde` or `serde_json`. A custom minimal JSON
reader/writer (`JsonReader`, `JsonWriter`) lives in `no-way-jose-core::json` and handles
header parsing and claim serialization. Two traits abstract the encoding boundary:

- `ToJson` — write JSON into a caller-provided `&mut Vec<u8>`
- `FromJson` — parse from `&[u8]`, returning `Box<dyn Error + Send + Sync>`

`RawJson` is the default payload type — it stores raw JSON bytes without parsing.

The JSON parser is intentionally strict: whitespace between tokens is rejected.
This is a deliberate design choice — JWTs should use compact JSON without
extraneous whitespace.

### JWE header parameter injection

Some JWE key management algorithms (AES-GCM-KW, ECDH-ES, PBES2) produce
parameters during encryption that must be included in the JWE protected header.
This is handled through `KeyEncryptionResult::extra_headers` — a vec of
`(key, raw_json_value)` pairs that are spliced into the header JSON before
base64url encoding and use as AAD. On decryption, `KeyDecryptor::decrypt_cek`
receives the raw header JSON bytes so algorithms can extract their parameters.

## Implementation Status

### Traits (no-way-jose-core)

- [x] `JwsAlgorithm`
- [x] `JweKeyManagement` / `JweContentEncryption`
- [x] `KeyEncryptor` / `KeyDecryptor` / `ContentEncryptor` / `ContentDecryptor`
- [x] `KeyEncryptionResult` (header parameter support)
- [x] `Purpose` / `Signed<A>` / `Encrypted<KM, CE>`
- [x] `HasKey<K>` / `KeyPurpose` (`Signing`, `Verifying`, `Encrypting`, `Decrypting`)
- [x] `Key<A, K>` / `SigningKey<A>` / `VerifyingKey<A>` / `EncryptionKey<KM>` / `DecryptionKey<KM>`
- [x] `Signer` / `Verifier`
- [x] `Dir` key management (direct key agreement)
- [x] `ToJson` / `FromJson` (custom, no serde dependency)
- [x] `JsonWriter::raw_value` (for header parameter injection)
- [x] `Validate` / `NoValidation`
- [x] `JoseError`

### Token types (no-way-jose-core)

- [x] `CompactToken<P, M>`
- [x] `UnsealedToken<P, M>`
- [x] `SignedData` / `EncryptedData`
- [x] `CompactJws<A, M>` / `UnsignedToken<A, M>` aliases
- [x] `CompactJwe<KM, CE, M>` alias
- [x] `UntypedCompactJws<M>` (dynamic algorithm path)
- [x] `FromStr` / `Display` for JWS 3-part and JWE 5-part compact serialization
- [x] Base64url encoding/decoding

### Header (no-way-jose-core)

- [x] `Header<'a>` view struct / `OwnedHeader`
- [x] `HeaderBuilder`
- [x] `raw_header_b64()` accessor

### Security hardening (no-way-jose-core)

- [x] `crit` header rejection (RFC 7515 §4.1.11)
- [x] `require_typ` validation (RFC 8725 §3.11), consumes self
- [x] `alg` header validated against type parameter at sign time
- [x] HMAC minimum key length enforced (32/48/64 bytes, RFC 7518 §3.2)
- [x] `Key` inner field private; `new`/`inner` are `#[doc(hidden)]`
- [x] Sealed trait via `#[doc(hidden)] pub mod __private`
- [x] `HeaderBuilder` uses `JsonWriter` (no JSON injection)

### Claims (no-way-jose-claims)

- [x] `RawJson` default payload type
- [x] `RegisteredClaims`
- [x] `HasExpiry` validator
- [x] `FromIssuer` validator
- [x] `ForAudience` validator
- [x] `Time` validator

### JWS Algorithms

- [x] `Es256` (no-way-jose-ecdsa) — P-256 / SHA-256
- [x] `Es384` (no-way-jose-ecdsa) — P-384 / SHA-384
- [x] `EdDsa` (no-way-jose-eddsa) — Ed25519
- [x] `Hs256` (no-way-jose-hmac) — HMAC-SHA-256
- [x] `Hs384` (no-way-jose-hmac) — HMAC-SHA-384
- [x] `Hs512` (no-way-jose-hmac) — HMAC-SHA-512
- [x] `Rs256` (no-way-jose-rsa) — RSASSA-PKCS1-v1_5 / SHA-256

### JWE Key Management Algorithms

- [x] `Dir` (no-way-jose-core) — Direct key agreement
- [x] `A128Kw` (no-way-jose-aes-kw) — AES-128 Key Wrap
- [x] `A192Kw` (no-way-jose-aes-kw) — AES-192 Key Wrap
- [x] `A256Kw` (no-way-jose-aes-kw) — AES-256 Key Wrap
- [x] `A128GcmKw` (no-way-jose-aes-gcm-kw) — AES-128-GCM Key Wrap
- [x] `A192GcmKw` (no-way-jose-aes-gcm-kw) — AES-192-GCM Key Wrap
- [x] `A256GcmKw` (no-way-jose-aes-gcm-kw) — AES-256-GCM Key Wrap
- [x] `Rsa1_5` (no-way-jose-rsa) — RSA PKCS#1 v1.5 (deprecated)
- [x] `RsaOaep` (no-way-jose-rsa) — RSA-OAEP SHA-1
- [x] `RsaOaep256` (no-way-jose-rsa) — RSA-OAEP SHA-256
- [x] `EcdhEs` (no-way-jose-ecdh-es) — ECDH-ES direct (P-256, P-384)
- [x] `EcdhEsA128Kw` (no-way-jose-ecdh-es) — ECDH-ES + A128KW
- [x] `EcdhEsA192Kw` (no-way-jose-ecdh-es) — ECDH-ES + A192KW
- [x] `EcdhEsA256Kw` (no-way-jose-ecdh-es) — ECDH-ES + A256KW
- [x] `Pbes2Hs256A128Kw` (no-way-jose-pbes2) — PBES2-HS256+A128KW
- [x] `Pbes2Hs384A192Kw` (no-way-jose-pbes2) — PBES2-HS384+A192KW
- [x] `Pbes2Hs512A256Kw` (no-way-jose-pbes2) — PBES2-HS512+A256KW

### JWE Content Encryption Algorithms

- [x] `A128CbcHs256` (no-way-jose-aes-cbc-hs) — AES-128-CBC + HMAC-SHA-256
- [x] `A192CbcHs384` (no-way-jose-aes-cbc-hs) — AES-192-CBC + HMAC-SHA-384
- [x] `A256CbcHs512` (no-way-jose-aes-cbc-hs) — AES-256-CBC + HMAC-SHA-512
- [x] `A128Gcm` (no-way-jose-aes-gcm) — AES-128-GCM
- [x] `A256Gcm` (no-way-jose-aes-gcm) — AES-256-GCM

### Tests (no-way-jose-test)

- [x] RFC 7515 Appendix A.1 — HS256 JWS test vector (strict header rejection)
- [x] RFC 7515 Appendix A.2 — RS256 JWS test vector
- [x] RFC 7515 Appendix A.3 — ES256 JWS test vector
- [x] RFC 7520 Section 4.4 — HS256 JWS test vector (with kid)
- [x] RFC 7520 Section 5.3 — PBES2-HS512+A256KW + A128CBC-HS256 JWE test vector
- [x] RFC 7520 Section 5.8 — A128KW + A128GCM JWE test vector
- [x] RFC 8037 Appendix A — EdDSA Ed25519 test vector
- [x] Sign/verify round-trip (ES256, ES384, EdDSA, HS256, HS384, HS512, RS256)
- [x] Key length enforcement (HS384 min 48, HS512 min 64)
- [x] Algorithm mismatch rejection
- [x] Claims validation (expiry, issuer, audience)
- [x] `UntypedCompactJws` dynamic dispatch
- [x] `require_typ` validation
- [x] `crit` header rejection
- [x] JWE dir + A256GCM round-trip, wrong key, tampered ciphertext, serialization
- [x] JWE dir + A128CBC-HS256, dir + A256CBC-HS512 round-trip
- [x] JWE A128KW + A128GCM, A256KW + A256GCM round-trip
- [x] JWE A128KW + A128CBC-HS256 round-trip
- [x] JWE RSA-OAEP + A256GCM, RSA-OAEP-256 + A128GCM round-trip
- [x] JWE RSA1_5 + A128CBC-HS256 round-trip
- [x] JWE A128GCMKW + A128GCM, A256GCMKW + A256GCM round-trip
- [x] JWE ECDH-ES + A256GCM (direct), ECDH-ES+A128KW + A128GCM round-trip
- [x] JWE PBES2-HS256+A128KW + A128GCM, PBES2-HS512+A256KW + A256GCM round-trip
- [x] JWE wrong key / wrong KEK / wrong password rejection
- [x] JWE header parameter verification (iv/tag for GCM-KW, epk for ECDH-ES, p2s/p2c for PBES2)

## Future Ideas

- **More JWS algorithms**: `Es512`, `Rs384`–`Rs512`, `Ps256`–`Ps512`
- **JWK / JWK Sets**: `Jwk`, `JwkSet`, `ToJwk`/`FromJwk` traits, JWK Thumbprint (RFC 7638)
- **Serde feature flag**: optional `serde` dep in `no-way-jose-core` providing blanket
  `ToJson`/`FromJson` for `Serialize`/`DeserializeOwned`
- **Header caching**: avoid re-decoding the header in `FromStr` → `header()` → `verify()`
- **Alternate crypto backends**: aws-lc-rs, ring, libsodium
- **`no_std` support**: no-way-jose-core is designed for it; algorithm crates may vary
- **JSON serialization mode**: JWS/JWE JSON serialization (non-compact), multiple signatures
- **Benchmarks**: Criterion benchmarks comparing against other Rust JOSE libraries
- **X25519 ECDH-ES**: extend no-way-jose-ecdh-es to support X25519 (via x25519-dalek)

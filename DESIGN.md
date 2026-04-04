# no-way-jose — Design Document

A type-safe Rust JOSE (JWS/JWE/JWT/JWK) library inspired by the
[paseto](https://github.com/conradludgate/paseto) crate's architecture.

## RFC References

| RFC  | Title                                              | Status      |
|------|----------------------------------------------------|-------------|
| 7515 | JSON Web Signature (JWS)                           | Done        |
| 7516 | JSON Web Encryption (JWE)                          | Planned     |
| 7517 | JSON Web Key (JWK)                                 | Planned     |
| 7518 | JSON Web Algorithms (JWA)                          | Done (JWS)  |
| 7519 | JSON Web Token (JWT)                               | Done        |
| 7520 | Examples of Protecting Content Using JOSE           | Test vectors|
| 7638 | JSON Web Key (JWK) Thumbprint                      | Planned     |
| 8037 | CFRG Elliptic Curve Diffie-Hellman and Signatures  | Done (EdDSA)|
| 8725 | JSON Web Token Best Current Practices              | Partial     |

## Crate Map

```
no-way-jose/
  jose-core/     Core traits, token types, base64url (no_std, no crypto deps)
  jose-json/     JSON Payload, registered JWT claims, validators
  jose-ecdsa/    ES256, ES384 (ECDSA JWS)
  jose-eddsa/    EdDSA Ed25519 (JWS)
  jose-hmac/     HS256, HS384, HS512 (HMAC JWS)
  jose-rsa/      RS256 (RSA PKCS#1 v1.5 JWS)
  jose-test/     Integration tests (unpublished)
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
  └─ Encrypted<KM,CE> 5-part compact: header.ek.iv.ct.tag  (future)

HasKey<K>             Maps algorithm → concrete key type
Signer / Verifier     Crypto entry points (impl by algorithm crates)
Payload               Encode/decode token body
Validate              Claims validation (composable)
```

### Token lifecycle

```
UnsealedToken::new(claims)
  │
  ├── .sign(key)   ──►  CompactToken<Signed<A>, M>  ──►  Display  ──►  wire
  │                                                           │
  │                      FromStr  ◄──  wire  ◄────────────────┘
  │                         │
  └── ◄── .verify(key, v) ─┘
```

### JSON handling

`jose-core` has no dependency on `serde` or `serde_json`. A custom minimal JSON
reader/writer (`JsonReader`, `JsonWriter`) lives in `jose-core::json` and handles
header parsing and claim serialization. Two traits abstract the encoding boundary:

- `ToJson` — write JSON into a caller-provided `&mut Vec<u8>`
- `FromJson` — parse from `&[u8]`, returning `Box<dyn Error + Send + Sync>`

`RawJson` is the default payload type — it stores raw JSON bytes without parsing.

The JSON parser is intentionally strict: whitespace between tokens is rejected.
This is a deliberate design choice — JWTs should use compact JSON without
extraneous whitespace.

## Implementation Status

### Traits (jose-core)

- [x] `JwsAlgorithm`
- [ ] `JweKeyManagement` (future)
- [ ] `JweContentEncryption` (future)
- [x] `Purpose` / `Signed<A>`
- [ ] `Encrypted<KM, CE>` (future)
- [x] `HasKey<K>` / `KeyPurpose`
- [x] `Key<A, K>` / `SigningKey<A>` / `VerifyingKey<A>`
- [x] `Signer` / `Verifier`
- [ ] `ContentEncrypt` / `KeyManage` (future)
- [x] `ToJson` / `FromJson` (custom, no serde dependency)
- [x] `Validate` / `NoValidation`
- [x] `JoseError`

### Token types (jose-core)

- [x] `CompactToken<P, M>`
- [x] `UnsealedToken<P, M>`
- [x] `SignedData`
- [ ] `EncryptedData` (future)
- [x] `CompactJws<A, M>` / `UnsignedToken<A, M>` aliases
- [x] `UntypedCompactJws<M>` (dynamic algorithm path)
- [x] `FromStr` / `Display` for JWS compact serialization
- [x] Base64url encoding/decoding

### Header (jose-core)

- [x] `Header<'a>` view struct / `OwnedHeader`
- [x] `HeaderBuilder`
- [x] `raw_header_b64()` accessor

### Security hardening (jose-core)

- [x] `crit` header rejection (RFC 7515 §4.1.11)
- [x] `require_typ` validation (RFC 8725 §3.11), consumes self
- [x] `alg` header validated against type parameter at sign time
- [x] HMAC minimum key length enforced (32/48/64 bytes, RFC 7518 §3.2)
- [x] `Key` inner field private; `new`/`inner` are `#[doc(hidden)]`
- [x] Sealed trait via `#[doc(hidden)] pub mod __private`
- [x] `HeaderBuilder` uses `JsonWriter` (no JSON injection)

### Claims (jose-json)

- [x] `RawJson` default payload type
- [x] `RegisteredClaims`
- [x] `HasExpiry` validator
- [x] `FromIssuer` validator
- [x] `ForAudience` validator
- [x] `Time` validator

### Algorithms

- [x] `Es256` (jose-ecdsa) — P-256 / SHA-256
- [x] `Es384` (jose-ecdsa) — P-384 / SHA-384
- [x] `EdDsa` (jose-eddsa) — Ed25519
- [x] `Hs256` (jose-hmac) — HMAC-SHA-256
- [x] `Hs384` (jose-hmac) — HMAC-SHA-384
- [x] `Hs512` (jose-hmac) — HMAC-SHA-512
- [x] `Rs256` (jose-rsa) — RSASSA-PKCS1-v1_5 / SHA-256

### Tests (jose-test)

- [x] RFC 7515 Appendix A.1 — HS256 JWS test vector (strict header rejection)
- [x] RFC 7515 Appendix A.2 — RS256 JWS test vector
- [x] RFC 7515 Appendix A.3 — ES256 JWS test vector
- [x] RFC 7520 Section 4.4 — HS256 JWS test vector (with kid)
- [x] RFC 8037 Appendix A — EdDSA Ed25519 test vector
- [x] Sign/verify round-trip (ES256, ES384, EdDSA, HS256, HS384, HS512, RS256)
- [x] Key length enforcement (HS384 min 48, HS512 min 64)
- [x] Algorithm mismatch rejection
- [x] Claims validation (expiry, issuer, audience)
- [x] `UntypedCompactJws` dynamic dispatch
- [x] `require_typ` validation
- [x] `crit` header rejection

## Future Ideas

- **More JWS algorithms**: `Es512`, `Rs384`–`Rs512`, `Ps256`–`Ps512`
- **JWE support**: `Encrypted<KM, CE>` purpose with AES-GCM, AES-CBC-HS content
  encryption and RSA-OAEP, AES-KW, ECDH-ES key management
- **JWK / JWK Sets**: `Jwk`, `JwkSet`, `ToJwk`/`FromJwk` traits, JWK Thumbprint (RFC 7638)
- **Serde feature flag**: optional `serde` dep in `jose-core` providing blanket
  `ToJson`/`FromJson` for `Serialize`/`DeserializeOwned`
- **Header caching**: avoid re-decoding the header in `FromStr` → `header()` → `verify()`
- **Alternate crypto backends**: aws-lc-rs, ring, libsodium
- **`no_std` support**: jose-core is designed for it; algorithm crates may vary
- **JSON serialization mode**: JWS/JWE JSON serialization (non-compact), multiple signatures
- **Benchmarks**: Criterion benchmarks comparing against other Rust JOSE libraries

# no-way-jose — Design Document

A type-safe Rust JOSE (JWS/JWE/JWT/JWK) library inspired by the
[paseto](https://github.com/conradludgate/paseto) crate's architecture.

## RFC References

| RFC  | Title                                              | Status      |
|------|----------------------------------------------------|-------------|
| 7515 | JSON Web Signature (JWS)                           | In progress |
| 7516 | JSON Web Encryption (JWE)                          | Planned     |
| 7517 | JSON Web Key (JWK)                                 | Planned     |
| 7518 | JSON Web Algorithms (JWA)                          | In progress |
| 7519 | JSON Web Token (JWT)                               | In progress |
| 7520 | Examples of Protecting Content Using JOSE           | Test vectors|
| 7638 | JSON Web Key (JWK) Thumbprint                      | Planned     |

## Crate Map

```
no-way-jose/
  jose-core/     Core traits, token types, base64url (no_std, no crypto deps)
  jose-json/     JSON Payload, registered JWT claims, validators
  jose-ecdsa/    ES256 (asymmetric JWS)
  jose-hmac/     HS256 (symmetric JWS)
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

Headers and JWS payloads are stored as `Box<serde_json::RawValue>` — no eager
deserialization. A borrowed `Header<'a>` view struct deserializes on demand.

## Implementation Status

### Traits (jose-core)

- [ ] `JwsAlgorithm`
- [ ] `JweKeyManagement` (future)
- [ ] `JweContentEncryption` (future)
- [ ] `Purpose` / `Signed<A>`
- [ ] `Encrypted<KM, CE>` (future)
- [ ] `HasKey<K>` / `KeyPurpose`
- [ ] `Key<A, K>` / `SigningKey<A>` / `VerifyingKey<A>`
- [ ] `Signer` / `Verifier`
- [ ] `ContentEncrypt` / `KeyManage` (future)
- [ ] `Payload`
- [ ] `Validate` / `NoValidation`
- [ ] `JoseError`

### Token types (jose-core)

- [ ] `CompactToken<P, M>`
- [ ] `UnsealedToken<P, M>`
- [ ] `SignedData`
- [ ] `EncryptedData` (future)
- [ ] `CompactJws<A, M>` / `UnsignedToken<A, M>` aliases
- [ ] `UntypedJws<M>` (dynamic algorithm path)
- [ ] `FromStr` / `Display` for JWS compact serialization
- [ ] Base64url encoding/decoding

### Header (jose-core)

- [ ] `Header<'a>` view struct
- [ ] `HeaderBuilder`
- [ ] `raw_header()` accessor

### Claims (jose-json)

- [ ] `Json<M>` payload wrapper
- [ ] `RegisteredClaims`
- [ ] `HasExpiry` validator
- [ ] `FromIssuer` validator
- [ ] `ForAudience` validator

### Algorithms

- [ ] `Es256` (jose-ecdsa) — P-256 / SHA-256
- [ ] `Hs256` (jose-hmac) — HMAC-SHA-256

### Tests (jose-test)

- [ ] RFC 7515 Appendix A.3 — ES256 JWS test vector
- [ ] RFC 7515 Appendix A.1 — HS256 JWS test vector
- [ ] RFC 7520 Section 4 — ECDSA test vectors
- [ ] Sign/verify round-trip (ES256, HS256)
- [ ] Algorithm mismatch rejection
- [ ] Claims validation (expiry, issuer, audience)

## Future Ideas

- **More JWS algorithms**: `Es384`, `Es512`, `Rs256`–`Rs512`, `Ps256`–`Ps512`, `EdDsa`
- **JWE support**: `Encrypted<KM, CE>` purpose with AES-GCM, AES-CBC-HS content
  encryption and RSA-OAEP, AES-KW, ECDH-ES key management
- **JWK / JWK Sets**: `Jwk`, `JwkSet`, `ToJwk`/`FromJwk` traits, JWK Thumbprint (RFC 7638)
- **Alternate crypto backends**: aws-lc-rs, ring, libsodium
- **`no_std` support**: jose-core is designed for it; algorithm crates may vary
- **JSON serialization mode**: JWS/JWE JSON serialization (non-compact), multiple signatures
- **Benchmarks**: Criterion benchmarks comparing against other Rust JOSE libraries

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.2](https://github.com/conradludgate/no-way-jose/compare/no-way-jose-core-v0.1.0-rc.1...no-way-jose-core-v0.1.0-rc.2) - 2026-04-08

### Other

- Bump all crate versions to 0.1.0-rc.2
- Add debug_assert guard to string_or_array for empty values
- Fix rebuild_header_with_extras for } inside string values
- Replace manual JWK array scanner with JsonReader::read_raw_array
- Reject leading zeros in skip_number to match JSON spec
- Refactor JsonReader to use sliding slice instead of input+pos
- Refactor read_string to use slice splitting instead of positional indexing
- Optimize JSON reader/writer with cold hints and cleanup
- Fix UTF-8 corruption in JSON string escaping
- Fix UTF-8 corruption in JSON string escaping
- Merge ContentEncryptor and ContentDecryptor into ContentCipher
- Unify JWE key management into single KeyManager trait

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-core-v0.1.0-rc.1) - 2026-04-07

### Fixed

- fix trait sealing

### Other

- fmt
- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Add dangerous_verify_without_signature to UntypedCompactJws
- Remove Sealed bound from algorithm traits
- Store raw compact string in CompactToken, defer base64 decoding
- Add from_bytes parsing for all compact token types
- Defer header serialization until sign/encrypt
- Switch JsonWriter, ToJson, and RawJson to use String instead of Vec<u8>
- Rename Jwk/JwkSet JSON methods to return String
- Replace JWK string fields with typed enums
- Add signature cache support: signing_input(), signature(), dangerous_verify_without_signature()
- Replace string errors with structured error-stack contexts
- Add cty header support and require_cty validation (RFC 7519 §5.2)
- Add UntypedCompactJwe for dynamic JWE algorithm dispatch
- Add TokenBuilder for fluent header construction
- fmt
- Improve JWK documentation with JWKS verification and thumbprint how-tos
- Enable clippy::pedantic across all crates and resolve all lints
- Add JWK support for HMAC keys (oct)
- Add JWK core types: Jwk, JwkSet, JwkParams, ToJwk/FromJwk traits
- Add cek_len to KeyDecryptor, deduplicate header scanning
- Unify header parsing and deduplicate JWS FromStr
- Extract shared header-field read helpers into core
- Add ECDH-ES key agreement (ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW)
- Extend KeyEncryptor/KeyDecryptor traits for header parameter support
- add README and rustdoc across all public API items
- rename all crates from jose-* to no-way-jose-*

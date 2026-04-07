# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-aes-gcm-kw-v0.1.0-rc.1) - 2026-04-07

### Other

- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Remove Sealed bound from algorithm traits
- Switch JsonWriter, ToJson, and RawJson to use String instead of Vec<u8>
- Replace JWK string fields with typed enums
- Replace string errors with structured error-stack contexts
- fmt
- Enable clippy::pedantic across all crates and resolve all lints
- Add JWK support for AES-KW, AES-GCM-KW, and ECDH-ES keys
- Add no_std and consistent core re-export to algorithm crates
- Add cek_len to KeyDecryptor, deduplicate header scanning
- Add AES-GCM key wrapping (A128GCMKW, A192GCMKW, A256GCMKW)

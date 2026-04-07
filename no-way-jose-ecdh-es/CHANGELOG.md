# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-ecdh-es-v0.1.0-rc.1) - 2026-04-07

### Fixed

- fix build

### Other

- Delete changelogs for unpublished crates to trigger re-release
- release v0.1.0-rc.1
- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Remove Sealed bound from algorithm traits
- Switch JsonWriter, ToJson, and RawJson to use String instead of Vec<u8>
- Replace JWK string fields with typed enums
- Replace string errors with structured error-stack contexts
- Add X25519 ECDH-ES key agreement (RFC 8037)
- fmt
- Enable clippy::pedantic across all crates and resolve all lints
- Add JWK support for AES-KW, AES-GCM-KW, and ECDH-ES keys
- Update rand and RustCrypto crates to latest versions
- Add no_std and consistent core re-export to algorithm crates
- Add cek_len to KeyDecryptor, deduplicate header scanning
- Add ECDH-ES key agreement (ECDH-ES, ECDH-ES+A128KW/A192KW/A256KW)

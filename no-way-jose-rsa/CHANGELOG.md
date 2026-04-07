# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-rsa-v0.1.0-rc.1) - 2026-04-07

### Fixed

- fix build

### Other

- Delete changelogs for unpublished crates to trigger re-release
- release v0.1.0-rc.1
- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Remove Sealed bound from algorithm traits
- Replace JWK string fields with typed enums
- Replace string errors with structured error-stack contexts
- Add Rs384, Rs512, Ps384, Ps512 JWS algorithms
- fmt
- Enable clippy::pedantic across all crates and resolve all lints
- Add JWK support for RSA keys (JWS and JWE)
- Add PS256 (RSA-PSS SHA-256) to no-way-jose-rsa
- Update rand and RustCrypto crates to latest versions
- Add no_std and consistent core re-export to algorithm crates
- Add cek_len to KeyDecryptor, deduplicate header scanning
- Extend KeyEncryptor/KeyDecryptor traits for header parameter support
- Add RSA JWE key management (RSA1_5, RSA-OAEP, RSA-OAEP-256)
- add README and rustdoc across all public API items
- rename all crates from jose-* to no-way-jose-*

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-ecdsa-v0.1.0-rc.1) - 2026-04-07

### Other

- fmt
- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Remove Sealed bound from algorithm traits
- Replace JWK string fields with typed enums
- Replace string errors with structured error-stack contexts
- Add Es512 (P-521/SHA-512) JWS algorithm
- fmt
- Enable clippy::pedantic across all crates and resolve all lints
- Add JWK support for ECDSA keys (EC, P-256/P-384)
- Add no_std and consistent core re-export to algorithm crates
- add README and rustdoc across all public API items
- rename all crates from jose-* to no-way-jose-*

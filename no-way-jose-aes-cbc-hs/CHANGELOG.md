# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-aes-cbc-hs-v0.1.0-rc.1) - 2026-04-07

### Other

- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Remove Sealed bound from algorithm traits
- Replace string errors with structured error-stack contexts
- fmt
- Enable clippy::pedantic across all crates and resolve all lints
- Update rand and RustCrypto crates to latest versions
- Add no_std and consistent core re-export to algorithm crates
- Add AES-CBC-HS content encryption (A128CBC-HS256, A192CBC-HS384, A256CBC-HS512)

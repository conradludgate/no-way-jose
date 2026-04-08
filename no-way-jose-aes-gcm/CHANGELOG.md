# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.3](https://github.com/conradludgate/no-way-jose/compare/no-way-jose-aes-gcm-v0.1.0-rc.2...no-way-jose-aes-gcm-v0.1.0-rc.3) - 2026-04-08

### Other

- improve JWE content encryption crate docs (aes-gcm, aes-cbc-hs)

## [0.1.0-rc.2](https://github.com/conradludgate/no-way-jose/compare/no-way-jose-aes-gcm-v0.1.0-rc.1...no-way-jose-aes-gcm-v0.1.0-rc.2) - 2026-04-08

### Other

- Bump all crate versions to 0.1.0-rc.2
- Merge ContentEncryptor and ContentDecryptor into ContentCipher

## [0.1.0-rc.1](https://github.com/conradludgate/no-way-jose/releases/tag/no-way-jose-aes-gcm-v0.1.0-rc.1) - 2026-04-07

### Other

- Add Apache-2.0 license and publish metadata
- Add per-crate READMEs and crate-level docs
- Bump all crate versions to 0.1.0-rc.1 and add metadata
- Remove Sealed bound from algorithm traits
- Replace string errors with structured error-stack contexts
- Add A192GCM content encryption algorithm
- fmt
- Enable clippy::pedantic across all crates and resolve all lints
- Add no_std and consistent core re-export to algorithm crates
- add README and rustdoc across all public API items
- rename all crates from jose-* to no-way-jose-*

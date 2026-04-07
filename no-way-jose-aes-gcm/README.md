# no-way-jose-aes-gcm

AES-GCM JWE content encryption algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | Key size | IV size | Tag size |
|-----------|----------|---------|----------|
| A128GCM | 16 bytes | 12 bytes | 16 bytes |
| A192GCM | 24 bytes | 12 bytes | 16 bytes |
| A256GCM | 32 bytes | 12 bytes | 16 bytes |

Uses the [RustCrypto](https://github.com/RustCrypto) `aes-gcm` crate. `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for JWE examples.

# no-way-jose-aes-gcm-kw

AES-GCM Key Wrap JWE key management algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | KEK size |
|-----------|----------|
| A128GCMKW | 16 bytes |
| A192GCMKW | 24 bytes |
| A256GCMKW | 32 bytes |

Wraps a randomly generated CEK using AES-GCM, with the IV and authentication tag transmitted in the JWE header (RFC 7518 §4.7). `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for JWE key wrapping examples.

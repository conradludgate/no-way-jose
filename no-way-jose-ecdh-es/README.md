# no-way-jose-ecdh-es

ECDH-ES JWE key agreement algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | Description |
|-----------|-------------|
| ECDH-ES | Direct key agreement |
| ECDH-ES+A128KW | ECDH-ES + AES-128 Key Wrap |
| ECDH-ES+A192KW | ECDH-ES + AES-192 Key Wrap |
| ECDH-ES+A256KW | ECDH-ES + AES-256 Key Wrap |

Supports P-256, P-384, and X25519 curves. Uses Concat KDF (RFC 7518 §4.6) for key derivation. `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for JWE examples.

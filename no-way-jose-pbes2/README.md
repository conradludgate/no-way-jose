# no-way-jose-pbes2

PBES2 password-based JWE key management for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | KDF | Key Wrap |
|-----------|-----|----------|
| PBES2-HS256+A128KW | PBKDF2-SHA-256 | AES-128 |
| PBES2-HS384+A192KW | PBKDF2-SHA-384 | AES-192 |
| PBES2-HS512+A256KW | PBKDF2-SHA-512 | AES-256 |

Derives a key encryption key from a password using PBKDF2, then wraps the CEK with AES Key Wrap (RFC 7518 §4.8). `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for JWE examples.

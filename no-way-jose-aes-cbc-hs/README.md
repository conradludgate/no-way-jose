# no-way-jose-aes-cbc-hs

AES-CBC + HMAC-SHA JWE content encryption algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | Encryption | Authentication | Key size |
|-----------|-----------|----------------|----------|
| A128CBC-HS256 | AES-128-CBC | HMAC-SHA-256 | 32 bytes |
| A192CBC-HS384 | AES-192-CBC | HMAC-SHA-384 | 48 bytes |
| A256CBC-HS512 | AES-256-CBC | HMAC-SHA-512 | 64 bytes |

Implements the composite Encrypt-then-MAC construction defined in RFC 7518 §5.2. `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for JWE examples.

# no-way-jose-aes-kw

AES Key Wrap JWE key management algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose).

| Algorithm | KEK size |
|-----------|----------|
| A128KW | 16 bytes |
| A192KW | 24 bytes |
| A256KW | 32 bytes |

Wraps a randomly generated Content Encryption Key (CEK) using AES Key Wrap (RFC 3394). `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for JWE key wrapping examples.

# no-way-jose-rsa

RSA algorithms for [no-way-jose](https://github.com/conradludgate/no-way-jose), covering both JWS signing and JWE key management.

### JWS signing

| Algorithm | Padding |
|-----------|---------|
| RS256, RS384, RS512 | RSASSA-PKCS1-v1_5 |
| PS256, PS384, PS512 | RSASSA-PSS |

### JWE key management

| Algorithm | Description |
|-----------|-------------|
| RSA1_5 | RSAES-PKCS1-v1_5 |
| RSA-OAEP | RSA-OAEP with SHA-1 |
| RSA-OAEP-256 | RSA-OAEP with SHA-256 |

Uses the [RustCrypto](https://github.com/RustCrypto) `rsa` crate. `#![no_std]` compatible.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for usage examples.

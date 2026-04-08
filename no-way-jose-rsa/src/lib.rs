//! RSA signing and content-key wrapping for JOSE: JWS with RSASSA-PKCS1-v1_5 / RSASSA-PSS,
//! and JWE with RSAES-PKCS1-v1_5 / RSA-OAEP (see [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518)).
//!
//! Keys use the [`rsa`] crate's [`rsa::RsaPrivateKey`] and [`rsa::RsaPublicKey`].
//!
//! ## JWS algorithms
//!
//! | JWS `alg` | Mechanism |
//! |-----------|-----------|
//! | RS256, RS384, RS512 | RSASSA-PKCS1-v1_5 (SHA-256 / SHA-384 / SHA-512) |
//! | PS256, PS384, PS512 | RSASSA-PSS with MGF1 (same hash) |
//!
//! ## JWE algorithms
//!
//! | JWE `alg` | Mechanism |
//! |-----------|-----------|
//! | `RSA1_5` | RSAES-PKCS1-v1_5 |
//! | `RSA-OAEP` | RSA-OAEP (SHA-1) |
//! | `RSA-OAEP-256` | RSA-OAEP (SHA-256) |
//!
//! Pair a key-management type (e.g. [`RsaOaep`]) with a content encryption implementation
//! from another crate (e.g. `no-way-jose-aes-gcm`) as the `CE` parameter to
//! [`no_way_jose_core::CompactJwe`].
//!
//! ## JWS: sign and verify
//!
//! ```
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::validation::NoValidation;
//! use no_way_jose_core::{CompactJws, UnsignedToken};
//! use no_way_jose_rsa::{signing_key, verifying_key_from_signing, Rs256};
//!
//! let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
//! let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
//! let sk = signing_key(private);
//! let vk = verifying_key_from_signing(&sk);
//!
//! let token_str = UnsignedToken::<Rs256, RawJson>::new(RawJson(r#"{"sub":"alice"}"#.into()))
//!     .sign(&sk)
//!     .unwrap()
//!     .to_string();
//!
//! let token: CompactJws<Rs256, RawJson> = token_str.parse().unwrap();
//! let verified = token
//!     .verify(&vk, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(verified.claims.0, r#"{"sub":"alice"}"#);
//! ```
//!
//! ## JWE: encrypt and decrypt
//!
//! ```
//! use no_way_jose_aes_gcm::A128Gcm;
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::purpose::Encrypted;
//! use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
//! use no_way_jose_core::validation::NoValidation;
//! use no_way_jose_rsa::{rsa_oaep, RsaOaep};
//!
//! let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
//! let private = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
//! let enc_key = rsa_oaep::key(private);
//!
//! let compact = UnsealedToken::<Encrypted<RsaOaep, A128Gcm>, RawJson>::new(RawJson(
//!     r#"{"secret":"message"}"#.into(),
//! ))
//! .encrypt(&enc_key)
//! .unwrap();
//! let token_str = compact.to_string();
//!
//! let token: CompactJwe<RsaOaep, A128Gcm, RawJson> = token_str.parse().unwrap();
//! let unsealed = token
//!     .decrypt(&enc_key, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(unsealed.claims.0, r#"{"secret":"message"}"#);
//! ```
//!
//! ## See also
//!
//! - [`no-way-jose-core`](https://docs.rs/no-way-jose-core) — tokens, traits, JSON types
//! - [`no-way-jose-claims`](https://docs.rs/no-way-jose-claims) — registered JWT claims and validation

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, RsaParams, RsaPrivateParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

macro_rules! rsa_jws_algorithm {
    ($name:ident, $alg:literal, $signing_key:ty, $verifying_key:ty, $sig_type:ty, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = rsa::RsaPrivateKey;
        }

        impl HasKey<Verifying> for $name {
            type Key = rsa::RsaPublicKey;
        }

        impl Signer for $name {
            fn sign(key: &rsa::RsaPrivateKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                use rsa::signature::{SignatureEncoding, Signer as _};
                let signing_key = <$signing_key>::new(key.clone());
                let sig = signing_key.sign(signing_input);
                Ok(sig.to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &rsa::RsaPublicKey,
                signing_input: &[u8],
                signature: &[u8],
            ) -> JoseResult<()> {
                use rsa::signature::Verifier as _;
                let verifying_key = <$verifying_key>::new(key.clone());
                let sig = <$sig_type>::try_from(signature)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                verifying_key
                    .verify(signing_input, &sig)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

rsa_jws_algorithm!(
    Rs256,
    "RS256",
    rsa::pkcs1v15::SigningKey<sha2::Sha256>,
    rsa::pkcs1v15::VerifyingKey<sha2::Sha256>,
    rsa::pkcs1v15::Signature,
    "RS256: RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 Section 3.3)."
);
rsa_jws_algorithm!(
    Rs384,
    "RS384",
    rsa::pkcs1v15::SigningKey<sha2::Sha384>,
    rsa::pkcs1v15::VerifyingKey<sha2::Sha384>,
    rsa::pkcs1v15::Signature,
    "RS384: RSASSA-PKCS1-v1_5 using SHA-384 (RFC 7518 Section 3.3)."
);
rsa_jws_algorithm!(
    Rs512,
    "RS512",
    rsa::pkcs1v15::SigningKey<sha2::Sha512>,
    rsa::pkcs1v15::VerifyingKey<sha2::Sha512>,
    rsa::pkcs1v15::Signature,
    "RS512: RSASSA-PKCS1-v1_5 using SHA-512 (RFC 7518 Section 3.3)."
);
rsa_jws_algorithm!(
    Ps256,
    "PS256",
    rsa::pss::SigningKey<sha2::Sha256>,
    rsa::pss::VerifyingKey<sha2::Sha256>,
    rsa::pss::Signature,
    "PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 Section 3.5)."
);
rsa_jws_algorithm!(
    Ps384,
    "PS384",
    rsa::pss::SigningKey<sha2::Sha384>,
    rsa::pss::VerifyingKey<sha2::Sha384>,
    rsa::pss::Signature,
    "PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384 (RFC 7518 Section 3.5)."
);
rsa_jws_algorithm!(
    Ps512,
    "PS512",
    rsa::pss::SigningKey<sha2::Sha512>,
    rsa::pss::VerifyingKey<sha2::Sha512>,
    rsa::pss::Signature,
    "PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512 (RFC 7518 Section 3.5)."
);

/// RS256 signing key.
pub type SigningKey = no_way_jose_core::SigningKey<Rs256>;
/// RS256 verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Rs256>;

/// Create an RS256 signing key from an RSA private key.
#[must_use]
pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
    no_way_jose_core::key::Key::new(private_key)
}

/// Create an RS256 verifying key from an RSA public key.
#[must_use]
pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(public_key)
}

/// Derive the RS256 verifying key from a signing key.
#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
}

// ====================================================================
// JWK support helpers
// ====================================================================

fn rsa_pubkey_to_jwk(key: &rsa::RsaPublicKey, alg: &str) -> Jwk {
    use rsa::traits::PublicKeyParts;
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Rsa(RsaParams {
            n: key.n_bytes().to_vec(),
            e: key.e_bytes().to_vec(),
            prv: None,
        }),
    }
}

fn rsa_privkey_to_jwk(key: &rsa::RsaPrivateKey, alg: &str) -> Jwk {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let primes = key.primes();
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Rsa(RsaParams {
            n: key.n_bytes().to_vec(),
            e: key.e_bytes().to_vec(),
            prv: Some(RsaPrivateParams {
                d: boxed_uint_to_be_bytes(key.d()),
                p: primes.first().map(boxed_uint_to_be_bytes),
                q: primes.get(1).map(boxed_uint_to_be_bytes),
                dp: key.dp().map(boxed_uint_to_be_bytes),
                dq: key.dq().map(boxed_uint_to_be_bytes),
                qi: key.crt_coefficient().map(|qi| boxed_uint_to_be_bytes(&qi)),
            }),
        }),
    }
}

fn boxed_uint_to_be_bytes(v: &rsa::BoxedUint) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

fn boxed_uint_from_be_bytes(bytes: &[u8]) -> rsa::BoxedUint {
    let bits = u32::try_from(bytes.len()).expect("key too large") * 8;
    let bits = bits.next_multiple_of(64);
    rsa::BoxedUint::from_be_slice(bytes, bits).expect("valid byte length")
}

fn validate_rsa_jwk(jwk: &Jwk, expected_alg: &str) -> JoseResult<()> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Rsa(_) => Ok(()),
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

fn rsa_pubkey_from_jwk(jwk: &Jwk) -> JoseResult<rsa::RsaPublicKey> {
    match &jwk.key {
        JwkParams::Rsa(p) => {
            if p.n.len() < 256 {
                return Err(Report::new(JoseError::InvalidKey));
            }
            let n = boxed_uint_from_be_bytes(&p.n);
            let e = boxed_uint_from_be_bytes(&p.e);
            rsa::RsaPublicKey::new_with_max_size(n, e, 16384)
                .map_err(|_| Report::new(JoseError::InvalidKey))
        }
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

fn rsa_privkey_from_jwk(jwk: &Jwk) -> JoseResult<rsa::RsaPrivateKey> {
    match &jwk.key {
        JwkParams::Rsa(p) => {
            if p.n.len() < 256 {
                return Err(Report::new(JoseError::InvalidKey));
            }
            let prv = p
                .prv
                .as_ref()
                .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
            let n = boxed_uint_from_be_bytes(&p.n);
            let e = boxed_uint_from_be_bytes(&p.e);
            let d = boxed_uint_from_be_bytes(&prv.d);
            let mut primes = Vec::new();
            if let Some(p_val) = &prv.p {
                primes.push(boxed_uint_from_be_bytes(p_val));
            }
            if let Some(q) = &prv.q {
                primes.push(boxed_uint_from_be_bytes(q));
            }
            rsa::RsaPrivateKey::from_components(n, e, d, primes)
                .map_err(|_| Report::new(JoseError::InvalidKey))
        }
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

macro_rules! rsa_jwk_impls {
    ($name:ident, $alg:literal, signing) => {
        impl JwkKeyConvert<Signing> for $name {
            fn key_to_jwk(key: &rsa::RsaPrivateKey) -> Jwk {
                rsa_privkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<rsa::RsaPrivateKey> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_privkey_from_jwk(jwk)
            }
        }
        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &rsa::RsaPublicKey) -> Jwk {
                rsa_pubkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<rsa::RsaPublicKey> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_pubkey_from_jwk(jwk)
            }
        }
    };
    ($name:ident, $alg:literal, encrypting) => {
        impl JwkKeyConvert<Encrypting> for $name {
            fn key_to_jwk(key: &rsa::RsaPrivateKey) -> Jwk {
                rsa_privkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> JoseResult<rsa::RsaPrivateKey> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_privkey_from_jwk(jwk)
            }
        }
    };
}

rsa_jwk_impls!(Rs256, "RS256", signing);
rsa_jwk_impls!(Rs384, "RS384", signing);
rsa_jwk_impls!(Rs512, "RS512", signing);
rsa_jwk_impls!(Ps256, "PS256", signing);
rsa_jwk_impls!(Ps384, "PS384", signing);
rsa_jwk_impls!(Ps512, "PS512", signing);

pub mod ps256 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps256>;

    #[must_use]
    pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
        no_way_jose_core::key::Key::new(private_key)
    }

    #[must_use]
    pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
    }
}

pub mod rs384 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Rs384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Rs384>;

    #[must_use]
    pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
        no_way_jose_core::key::Key::new(private_key)
    }

    #[must_use]
    pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
    }
}

pub mod rs512 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Rs512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Rs512>;

    #[must_use]
    pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
        no_way_jose_core::key::Key::new(private_key)
    }

    #[must_use]
    pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
    }
}

pub mod ps384 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps384>;

    #[must_use]
    pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
        no_way_jose_core::key::Key::new(private_key)
    }

    #[must_use]
    pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
    }
}

pub mod ps512 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps512>;

    #[must_use]
    pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
        no_way_jose_core::key::Key::new(private_key)
    }

    #[must_use]
    pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
    }
}

// ====================================================================
// JWE key management algorithms
// ====================================================================

use no_way_jose_core::jwe_algorithm::{JweKeyManagement, KeyEncryptionResult, KeyManager};
use no_way_jose_core::key::Encrypting;

macro_rules! rsa_kw_algorithm {
    ($name:ident, $alg:literal, $pad_encrypt:expr, $pad_decrypt:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl JweKeyManagement for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Encrypting> for $name {
            type Key = rsa::RsaPrivateKey;
        }

        impl KeyManager for $name {
            fn encrypt_cek(
                key: &rsa::RsaPrivateKey,
                cek_len: usize,
            ) -> JoseResult<KeyEncryptionResult> {
                let pub_key = key.to_public_key();
                let mut cek = vec![0u8; cek_len];
                getrandom::fill(&mut cek).map_err(|_| Report::new(JoseError::CryptoError))?;

                let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
                let encrypted_key = pub_key
                    .encrypt(&mut rng, $pad_encrypt, &cek)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;

                Ok(KeyEncryptionResult {
                    encrypted_key,
                    cek,
                    extra_headers: Vec::new(),
                })
            }

            fn decrypt_cek(
                key: &rsa::RsaPrivateKey,
                encrypted_key: &[u8],
                _header: &[u8],
                _cek_len: usize,
            ) -> JoseResult<Vec<u8>> {
                key.decrypt($pad_decrypt, encrypted_key)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

rsa_kw_algorithm!(
    Rsa1_5,
    "RSA1_5",
    rsa::Pkcs1v15Encrypt,
    rsa::Pkcs1v15Encrypt,
    "RSA PKCS#1 v1.5 key encryption (RFC 7518 §4.2). Deprecated; prefer RSA-OAEP."
);

rsa_kw_algorithm!(
    RsaOaep,
    "RSA-OAEP",
    rsa::Oaep::<sha1::Sha1>::new(),
    rsa::Oaep::<sha1::Sha1>::new(),
    "RSA-OAEP with SHA-1 key encryption (RFC 7518 §4.3)."
);

rsa_kw_algorithm!(
    RsaOaep256,
    "RSA-OAEP-256",
    rsa::Oaep::<sha2::Sha256>::new(),
    rsa::Oaep::<sha2::Sha256>::new(),
    "RSA-OAEP with SHA-256 key encryption (RFC 7518 §4.3)."
);

rsa_jwk_impls!(Rsa1_5, "RSA1_5", encrypting);
rsa_jwk_impls!(RsaOaep, "RSA-OAEP", encrypting);
rsa_jwk_impls!(RsaOaep256, "RSA-OAEP-256", encrypting);

pub mod rsa1_5 {
    pub type Key = no_way_jose_core::EncryptionKey<super::Rsa1_5>;

    #[must_use]
    pub fn key(private_key: rsa::RsaPrivateKey) -> Key {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod rsa_oaep {
    pub type Key = no_way_jose_core::EncryptionKey<super::RsaOaep>;

    #[must_use]
    pub fn key(private_key: rsa::RsaPrivateKey) -> Key {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod rsa_oaep_256 {
    pub type Key = no_way_jose_core::EncryptionKey<super::RsaOaep256>;

    #[must_use]
    pub fn key(private_key: rsa::RsaPrivateKey) -> Key {
        no_way_jose_core::key::Key::new(private_key)
    }
}

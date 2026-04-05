//! RSA algorithms for JWS signing ([`Rs256`], [`Ps256`]) and JWE key management
//! ([`Rsa1_5`], [`RsaOaep`], [`RsaOaep256`]).
//!
//! Keys are constructed from the `rsa` crate's [`rsa::RsaPrivateKey`] and
//! [`rsa::RsaPublicKey`] types.

#![no_std]

extern crate alloc;

pub use no_way_jose_core;

use alloc::vec;
use alloc::vec::Vec;
use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, RsaParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

/// RS256: RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 Section 3.3).
pub struct Rs256;

impl no_way_jose_core::__private::Sealed for Rs256 {}

impl JwsAlgorithm for Rs256 {
    const ALG: &'static str = "RS256";
}

impl HasKey<Signing> for Rs256 {
    type Key = rsa::RsaPrivateKey;
}

impl HasKey<Verifying> for Rs256 {
    type Key = rsa::RsaPublicKey;
}

impl Signer for Rs256 {
    fn sign(key: &rsa::RsaPrivateKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_key = SigningKey::<sha2::Sha256>::new(key.clone());
        let sig = signing_key.sign(signing_input);
        Ok(sig.to_vec())
    }
}

impl Verifier for Rs256 {
    fn verify(
        key: &rsa::RsaPublicKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(key.clone());
        let sig =
            rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| JoseError::CryptoError)?;
        verifying_key
            .verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

/// RS256 signing key.
pub type SigningKey = no_way_jose_core::SigningKey<Rs256>;
/// RS256 verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Rs256>;

/// Create an RS256 signing key from an RSA private key.
pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
    no_way_jose_core::key::Key::new(private_key)
}

/// Create an RS256 verifying key from an RSA public key.
pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(public_key)
}

/// Derive the RS256 verifying key from a signing key.
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
}

// ====================================================================
// JWK support helpers
// ====================================================================

fn rsa_pubkey_to_jwk(key: &rsa::RsaPublicKey, alg: &str) -> Jwk {
    use rsa::traits::PublicKeyParts;
    Jwk {
        kty: "RSA".into(),
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        params: JwkParams::Rsa(RsaParams {
            n: key.n_bytes().to_vec(),
            e: key.e_bytes().to_vec(),
            d: None,
            p: None,
            q: None,
            dp: None,
            dq: None,
            qi: None,
        }),
    }
}

fn rsa_privkey_to_jwk(key: &rsa::RsaPrivateKey, alg: &str) -> Jwk {
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};
    let primes = key.primes();
    let mut jwk = Jwk {
        kty: "RSA".into(),
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        params: JwkParams::Rsa(RsaParams {
            n: key.n_bytes().to_vec(),
            e: key.e_bytes().to_vec(),
            d: Some(boxed_uint_to_be_bytes(key.d())),
            p: primes.first().map(boxed_uint_to_be_bytes),
            q: primes.get(1).map(boxed_uint_to_be_bytes),
            dp: key.dp().map(boxed_uint_to_be_bytes),
            dq: key.dq().map(boxed_uint_to_be_bytes),
            qi: None,
        }),
    };
    if let Some(qi) = key.crt_coefficient() {
        if let JwkParams::Rsa(ref mut p) = jwk.params {
            p.qi = Some(boxed_uint_to_be_bytes(&qi));
        }
    }
    jwk
}

fn boxed_uint_to_be_bytes(v: &rsa::BoxedUint) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

fn boxed_uint_from_be_bytes(bytes: &[u8]) -> rsa::BoxedUint {
    let bits = (bytes.len() as u32 * 8).next_multiple_of(64);
    rsa::BoxedUint::from_be_slice(bytes, bits).expect("valid byte length")
}

fn validate_rsa_jwk(jwk: &Jwk, expected_alg: &str) -> Result<(), JoseError> {
    if jwk.kty != "RSA" {
        return Err(JoseError::InvalidKey);
    }
    if let Some(alg) = &jwk.alg {
        if alg != expected_alg {
            return Err(JoseError::InvalidKey);
        }
    }
    Ok(())
}

fn rsa_pubkey_from_jwk(jwk: &Jwk) -> Result<rsa::RsaPublicKey, JoseError> {
    match &jwk.params {
        JwkParams::Rsa(p) => {
            let n = boxed_uint_from_be_bytes(&p.n);
            let e = boxed_uint_from_be_bytes(&p.e);
            rsa::RsaPublicKey::new_with_max_size(n, e, 16384).map_err(|_| JoseError::InvalidKey)
        }
        _ => Err(JoseError::InvalidKey),
    }
}

fn rsa_privkey_from_jwk(jwk: &Jwk) -> Result<rsa::RsaPrivateKey, JoseError> {
    match &jwk.params {
        JwkParams::Rsa(p) => {
            let n = boxed_uint_from_be_bytes(&p.n);
            let e = boxed_uint_from_be_bytes(&p.e);
            let d = boxed_uint_from_be_bytes(p.d.as_ref().ok_or(JoseError::InvalidKey)?);
            let mut primes = Vec::new();
            if let Some(p_val) = &p.p {
                primes.push(boxed_uint_from_be_bytes(p_val));
            }
            if let Some(q) = &p.q {
                primes.push(boxed_uint_from_be_bytes(q));
            }
            rsa::RsaPrivateKey::from_components(n, e, d, primes).map_err(|_| JoseError::InvalidKey)
        }
        _ => Err(JoseError::InvalidKey),
    }
}

macro_rules! rsa_jwk_impls {
    ($name:ident, $alg:literal, signing) => {
        impl JwkKeyConvert<Signing> for $name {
            fn key_to_jwk(key: &rsa::RsaPrivateKey) -> Jwk {
                rsa_privkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<rsa::RsaPrivateKey, JoseError> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_privkey_from_jwk(jwk)
            }
        }
        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &rsa::RsaPublicKey) -> Jwk {
                rsa_pubkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<rsa::RsaPublicKey, JoseError> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_pubkey_from_jwk(jwk)
            }
        }
    };
    ($name:ident, $alg:literal, encrypting) => {
        impl JwkKeyConvert<Encrypting> for $name {
            fn key_to_jwk(key: &rsa::RsaPublicKey) -> Jwk {
                rsa_pubkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<rsa::RsaPublicKey, JoseError> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_pubkey_from_jwk(jwk)
            }
        }
        impl JwkKeyConvert<Decrypting> for $name {
            fn key_to_jwk(key: &rsa::RsaPrivateKey) -> Jwk {
                rsa_privkey_to_jwk(key, $alg)
            }
            fn key_from_jwk(jwk: &Jwk) -> Result<rsa::RsaPrivateKey, JoseError> {
                validate_rsa_jwk(jwk, $alg)?;
                rsa_privkey_from_jwk(jwk)
            }
        }
    };
}

rsa_jwk_impls!(Rs256, "RS256", signing);

// ====================================================================
// PS256: RSA-PSS
// ====================================================================

/// PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 Section 3.5).
pub struct Ps256;

impl no_way_jose_core::__private::Sealed for Ps256 {}

impl JwsAlgorithm for Ps256 {
    const ALG: &'static str = "PS256";
}

impl HasKey<Signing> for Ps256 {
    type Key = rsa::RsaPrivateKey;
}

impl HasKey<Verifying> for Ps256 {
    type Key = rsa::RsaPublicKey;
}

impl Signer for Ps256 {
    fn sign(key: &rsa::RsaPrivateKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        use rsa::pss::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let signing_key = SigningKey::<sha2::Sha256>::new(key.clone());
        let sig = signing_key.sign(signing_input);
        Ok(sig.to_vec())
    }
}

impl Verifier for Ps256 {
    fn verify(
        key: &rsa::RsaPublicKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        use rsa::pss::VerifyingKey;
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(key.clone());
        let sig = rsa::pss::Signature::try_from(signature).map_err(|_| JoseError::CryptoError)?;
        verifying_key
            .verify(signing_input, &sig)
            .map_err(|_| JoseError::CryptoError)
    }
}

rsa_jwk_impls!(Ps256, "PS256", signing);

pub mod ps256 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps256>;

    pub fn signing_key(private_key: rsa::RsaPrivateKey) -> SigningKey {
        no_way_jose_core::key::Key::new(private_key)
    }

    pub fn verifying_key(public_key: rsa::RsaPublicKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(rsa::RsaPublicKey::from(key.inner()))
    }
}

// ====================================================================
// JWE key management algorithms
// ====================================================================

use no_way_jose_core::__private::Sealed;
use no_way_jose_core::jwe_algorithm::{
    JweKeyManagement, KeyDecryptor, KeyEncryptionResult, KeyEncryptor,
};
use no_way_jose_core::key::{Decrypting, Encrypting};

macro_rules! rsa_kw_algorithm {
    ($name:ident, $alg:literal, $pad_encrypt:expr, $pad_decrypt:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl Sealed for $name {}

        impl JweKeyManagement for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Encrypting> for $name {
            type Key = rsa::RsaPublicKey;
        }

        impl HasKey<Decrypting> for $name {
            type Key = rsa::RsaPrivateKey;
        }

        impl KeyEncryptor for $name {
            fn encrypt_cek(
                key: &rsa::RsaPublicKey,
                cek_len: usize,
            ) -> Result<KeyEncryptionResult, JoseError> {
                let mut cek = vec![0u8; cek_len];
                getrandom::fill(&mut cek).map_err(|_| JoseError::CryptoError)?;

                let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
                let encrypted_key = key
                    .encrypt(&mut rng, $pad_encrypt, &cek)
                    .map_err(|_| JoseError::CryptoError)?;

                Ok(KeyEncryptionResult {
                    encrypted_key,
                    cek,
                    extra_headers: Vec::new(),
                })
            }
        }

        impl KeyDecryptor for $name {
            fn decrypt_cek(
                key: &rsa::RsaPrivateKey,
                encrypted_key: &[u8],
                _header: &[u8],
                _cek_len: usize,
            ) -> Result<Vec<u8>, JoseError> {
                key.decrypt($pad_decrypt, encrypted_key)
                    .map_err(|_| JoseError::CryptoError)
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
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::Rsa1_5>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::Rsa1_5>;

    pub fn encryption_key(public_key: rsa::RsaPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    pub fn decryption_key(private_key: rsa::RsaPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod rsa_oaep {
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::RsaOaep>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::RsaOaep>;

    pub fn encryption_key(public_key: rsa::RsaPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    pub fn decryption_key(private_key: rsa::RsaPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

pub mod rsa_oaep_256 {
    pub type EncryptionKey = no_way_jose_core::EncryptionKey<super::RsaOaep256>;
    pub type DecryptionKey = no_way_jose_core::DecryptionKey<super::RsaOaep256>;

    pub fn encryption_key(public_key: rsa::RsaPublicKey) -> EncryptionKey {
        no_way_jose_core::key::Key::new(public_key)
    }

    pub fn decryption_key(private_key: rsa::RsaPrivateKey) -> DecryptionKey {
        no_way_jose_core::key::Key::new(private_key)
    }
}

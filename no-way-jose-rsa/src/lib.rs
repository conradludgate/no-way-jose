//! RSA algorithms for JWS signing ([`Rs256`]) and JWE key management
//! ([`Rsa1_5`], [`RsaOaep`], [`RsaOaep256`]).
//!
//! Keys are constructed from the `rsa` crate's [`rsa::RsaPrivateKey`] and
//! [`rsa::RsaPublicKey`] types.

pub use no_way_jose_core;

use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
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

                let mut rng = rsa::rand_core::OsRng;
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
    rsa::Oaep::new::<sha1::Sha1>(),
    rsa::Oaep::new::<sha1::Sha1>(),
    "RSA-OAEP with SHA-1 key encryption (RFC 7518 §4.3)."
);

rsa_kw_algorithm!(
    RsaOaep256,
    "RSA-OAEP-256",
    rsa::Oaep::new::<sha2::Sha256>(),
    rsa::Oaep::new::<sha2::Sha256>(),
    "RSA-OAEP with SHA-256 key encryption (RFC 7518 §4.3)."
);

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

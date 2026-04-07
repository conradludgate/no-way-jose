use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair, UnparsedPublicKey};
use error_stack::Report;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{EcCurve, EcParams, Jwk, JwkKeyConvert, JwkParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

pub struct EcdsaVerifyingKey {
    bytes: Vec<u8>,
}

macro_rules! ecdsa_algorithm {
    (
        $name:ident, $alg:literal,
        $signing_alg:expr, $verify_alg:expr,
        $crv:expr, $scalar_len:literal,
        $doc:literal
    ) => {
        #[doc = $doc]
        pub struct $name;

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = EcdsaKeyPair;
        }

        impl HasKey<Verifying> for $name {
            type Key = EcdsaVerifyingKey;
        }

        impl Signer for $name {
            fn sign(key: &EcdsaKeyPair, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                let rng = SystemRandom::new();
                let sig = key
                    .sign(&rng, signing_input)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(sig.as_ref().to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(key: &EcdsaVerifyingKey, signing_input: &[u8], sig: &[u8]) -> JoseResult<()> {
                let pk = UnparsedPublicKey::new($verify_alg, &key.bytes);
                pk.verify(signing_input, sig)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }

        impl JwkKeyConvert<Signing> for $name {
            fn key_to_jwk(key: &EcdsaKeyPair) -> Jwk {
                let pub_bytes = key.public_key().as_ref();
                let d_bytes: EcPrivateKeyBin =
                    key.private_key().as_be_bytes().expect("private key export");
                ec_signing_to_jwk(pub_bytes, d_bytes.as_ref(), $alg, $crv, $scalar_len)
            }

            fn key_from_jwk(jwk: &Jwk) -> JoseResult<EcdsaKeyPair> {
                validate_ec_jwk(jwk, $alg, $crv)?;
                match &jwk.key {
                    JwkParams::Ec(p) => {
                        let d =
                            p.d.as_ref()
                                .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                        let mut uncompressed = Vec::with_capacity(1 + p.x.len() + p.y.len());
                        uncompressed.push(0x04);
                        uncompressed.extend_from_slice(&p.x);
                        uncompressed.extend_from_slice(&p.y);
                        EcdsaKeyPair::from_private_key_and_public_key(
                            $signing_alg,
                            d,
                            &uncompressed,
                        )
                        .map_err(|_| Report::new(JoseError::InvalidKey))
                    }
                    _ => Err(Report::new(JoseError::InvalidKey)),
                }
            }
        }

        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &EcdsaVerifyingKey) -> Jwk {
                ec_verifying_to_jwk(&key.bytes, $alg, $crv, $scalar_len)
            }

            fn key_from_jwk(jwk: &Jwk) -> JoseResult<EcdsaVerifyingKey> {
                validate_ec_jwk(jwk, $alg, $crv)?;
                match &jwk.key {
                    JwkParams::Ec(p) => {
                        let mut uncompressed = Vec::with_capacity(1 + p.x.len() + p.y.len());
                        uncompressed.push(0x04);
                        uncompressed.extend_from_slice(&p.x);
                        uncompressed.extend_from_slice(&p.y);
                        Ok(EcdsaVerifyingKey {
                            bytes: uncompressed,
                        })
                    }
                    _ => Err(Report::new(JoseError::InvalidKey)),
                }
            }
        }
    };
}

fn ec_signing_to_jwk(
    pub_bytes: &[u8],
    d_bytes: &[u8],
    alg: &str,
    crv: EcCurve,
    scalar_len: usize,
) -> Jwk {
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Ec(EcParams {
            crv,
            x: pub_bytes[1..=scalar_len].to_vec(),
            y: pub_bytes[1 + scalar_len..].to_vec(),
            d: Some(d_bytes.to_vec()),
        }),
    }
}

fn ec_verifying_to_jwk(pub_bytes: &[u8], alg: &str, crv: EcCurve, scalar_len: usize) -> Jwk {
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Ec(EcParams {
            crv,
            x: pub_bytes[1..=scalar_len].to_vec(),
            y: pub_bytes[1 + scalar_len..].to_vec(),
            d: None,
        }),
    }
}

fn validate_ec_jwk(jwk: &Jwk, expected_alg: &str, expected_crv: EcCurve) -> JoseResult<()> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Ec(p) if p.crv == expected_crv => Ok(()),
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

ecdsa_algorithm!(
    Es256,
    "ES256",
    &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
    &signature::ECDSA_P256_SHA256_FIXED,
    EcCurve::P256,
    32,
    "ES256: ECDSA using P-256 and SHA-256 (aws-lc-rs backend)."
);

ecdsa_algorithm!(
    Es384,
    "ES384",
    &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
    &signature::ECDSA_P384_SHA384_FIXED,
    EcCurve::P384,
    48,
    "ES384: ECDSA using P-384 and SHA-384 (aws-lc-rs backend)."
);

ecdsa_algorithm!(
    Es512,
    "ES512",
    &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
    &signature::ECDSA_P521_SHA512_FIXED,
    EcCurve::P521,
    66,
    "ES512: ECDSA using P-521 and SHA-512 (aws-lc-rs backend)."
);

fn make_signing_key(alg: &'static EcdsaSigningAlgorithm, pkcs8: &[u8]) -> JoseResult<EcdsaKeyPair> {
    EcdsaKeyPair::from_pkcs8(alg, pkcs8).map_err(|_| Report::new(JoseError::InvalidKey))
}

pub type SigningKey = no_way_jose_core::SigningKey<Es256>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es256>;

/// Create an ES256 signing key from PKCS#8 DER bytes.
///
/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_pkcs8_der(bytes: &[u8]) -> JoseResult<SigningKey> {
    make_signing_key(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, bytes)
        .map(no_way_jose_core::key::Key::new)
}

/// Create an ES256 verifying key from uncompressed SEC1 public key bytes (0x04 || x || y).
///
/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn verifying_key_from_public_bytes(bytes: &[u8]) -> JoseResult<VerifyingKey> {
    let pk = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, bytes);
    pk.verify(b"", b"").ok();
    Ok(no_way_jose_core::key::Key::new(EcdsaVerifyingKey {
        bytes: bytes.to_vec(),
    }))
}

/// Extract the verifying key from a signing key pair.
#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(EcdsaVerifyingKey {
        bytes: key.inner().public_key().as_ref().to_vec(),
    })
}

pub mod es384 {
    use aws_lc_rs::signature;
    use no_way_jose_core::error::JoseResult;

    use super::{EcdsaVerifyingKey, Es384};

    pub type SigningKey = no_way_jose_core::SigningKey<Es384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es384>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn signing_key_from_pkcs8_der(bytes: &[u8]) -> JoseResult<SigningKey> {
        super::make_signing_key(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, bytes)
            .map(no_way_jose_core::key::Key::new)
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn verifying_key_from_public_bytes(bytes: &[u8]) -> JoseResult<VerifyingKey> {
        Ok(no_way_jose_core::key::Key::new(EcdsaVerifyingKey {
            bytes: bytes.to_vec(),
        }))
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        use aws_lc_rs::signature::KeyPair;
        no_way_jose_core::key::Key::new(EcdsaVerifyingKey {
            bytes: key.inner().public_key().as_ref().to_vec(),
        })
    }
}

pub mod es512 {
    use aws_lc_rs::signature;
    use no_way_jose_core::error::JoseResult;

    use super::{EcdsaVerifyingKey, Es512};

    pub type SigningKey = no_way_jose_core::SigningKey<Es512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es512>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn signing_key_from_pkcs8_der(bytes: &[u8]) -> JoseResult<SigningKey> {
        super::make_signing_key(&signature::ECDSA_P521_SHA512_FIXED_SIGNING, bytes)
            .map(no_way_jose_core::key::Key::new)
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn verifying_key_from_public_bytes(bytes: &[u8]) -> JoseResult<VerifyingKey> {
        Ok(no_way_jose_core::key::Key::new(EcdsaVerifyingKey {
            bytes: bytes.to_vec(),
        }))
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        use aws_lc_rs::signature::KeyPair;
        no_way_jose_core::key::Key::new(EcdsaVerifyingKey {
            bytes: key.inner().public_key().as_ref().to_vec(),
        })
    }
}

use error_stack::Report;
use graviola::hashing::{Sha256, Sha384};
use graviola::signing::ecdsa;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{EcCurve, EcParams, Jwk, JwkKeyConvert, JwkParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

macro_rules! ecdsa_algorithm {
    ($name:ident, $alg:literal, $curve:ty, $hash:ty, $sig_len:literal, $doc:literal) => {
        #[doc = $doc]
        pub struct $name;

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = ecdsa::SigningKey<$curve>;
        }

        impl HasKey<Verifying> for $name {
            type Key = ecdsa::VerifyingKey<$curve>;
        }

        impl Signer for $name {
            fn sign(key: &ecdsa::SigningKey<$curve>, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                let mut buf = [0u8; $sig_len];
                let sig = key
                    .sign::<$hash>(&[signing_input], &mut buf)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(sig.to_vec())
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &ecdsa::VerifyingKey<$curve>,
                signing_input: &[u8],
                signature: &[u8],
            ) -> JoseResult<()> {
                key.verify::<$hash>(&[signing_input], signature)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

ecdsa_algorithm!(
    Es256,
    "ES256",
    ecdsa::P256,
    Sha256,
    64,
    "ES256: ECDSA using P-256 and SHA-256 (graviola backend)."
);

ecdsa_algorithm!(
    Es384,
    "ES384",
    ecdsa::P384,
    Sha384,
    96,
    "ES384: ECDSA using P-384 and SHA-384 (graviola backend)."
);

// -- JWK support --

macro_rules! ecdsa_jwk_impls {
    ($name:ident, $alg:literal, $crv:expr, $curve:ty, $privkey:ty, $pubkey:ty, $scalar_len:literal) => {
        impl JwkKeyConvert<Signing> for $name {
            fn key_to_jwk(key: &ecdsa::SigningKey<$curve>) -> Jwk {
                let d = key.private_key.as_bytes();
                let point = key.private_key.public_key_uncompressed();
                Jwk {
                    kid: None,
                    alg: Some($alg.into()),
                    use_: None,
                    key_ops: None,
                    key: JwkParams::Ec(EcParams {
                        crv: $crv,
                        x: point[1..1 + $scalar_len].to_vec(),
                        y: point[1 + $scalar_len..].to_vec(),
                        d: Some(d.to_vec()),
                    }),
                }
            }

            fn key_from_jwk(jwk: &Jwk) -> JoseResult<ecdsa::SigningKey<$curve>> {
                validate_ec_jwk(jwk, $alg, $crv)?;
                match &jwk.key {
                    JwkParams::Ec(p) => {
                        let d =
                            p.d.as_ref()
                                .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                        let private_key = <$privkey>::from_bytes(d)
                            .map_err(|_| Report::new(JoseError::InvalidKey))?;
                        Ok(ecdsa::SigningKey { private_key })
                    }
                    _ => Err(Report::new(JoseError::InvalidKey)),
                }
            }
        }

        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &ecdsa::VerifyingKey<$curve>) -> Jwk {
                let point = key.public_key.as_bytes_uncompressed();
                Jwk {
                    kid: None,
                    alg: Some($alg.into()),
                    use_: None,
                    key_ops: None,
                    key: JwkParams::Ec(EcParams {
                        crv: $crv,
                        x: point[1..1 + $scalar_len].to_vec(),
                        y: point[1 + $scalar_len..].to_vec(),
                        d: None,
                    }),
                }
            }

            fn key_from_jwk(jwk: &Jwk) -> JoseResult<ecdsa::VerifyingKey<$curve>> {
                validate_ec_jwk(jwk, $alg, $crv)?;
                match &jwk.key {
                    JwkParams::Ec(p) => {
                        let mut uncompressed = Vec::with_capacity(1 + p.x.len() + p.y.len());
                        uncompressed.push(0x04);
                        uncompressed.extend_from_slice(&p.x);
                        uncompressed.extend_from_slice(&p.y);
                        let public_key = <$pubkey>::from_x962_uncompressed(&uncompressed)
                            .map_err(|_| Report::new(JoseError::InvalidKey))?;
                        Ok(ecdsa::VerifyingKey { public_key })
                    }
                    _ => Err(Report::new(JoseError::InvalidKey)),
                }
            }
        }
    };
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

ecdsa_jwk_impls!(
    Es256,
    "ES256",
    EcCurve::P256,
    ecdsa::P256,
    graviola::key_agreement::p256::StaticPrivateKey,
    graviola::key_agreement::p256::PublicKey,
    32
);
ecdsa_jwk_impls!(
    Es384,
    "ES384",
    EcCurve::P384,
    ecdsa::P384,
    graviola::key_agreement::p384::StaticPrivateKey,
    graviola::key_agreement::p384::PublicKey,
    48
);

pub type SigningKey = no_way_jose_core::SigningKey<Es256>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es256>;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_sec1_der(bytes: &[u8]) -> JoseResult<SigningKey> {
    ecdsa::SigningKey::from_sec1_der(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn verifying_key_from_x962(bytes: &[u8]) -> JoseResult<VerifyingKey> {
    ecdsa::VerifyingKey::from_x962_uncompressed(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

pub mod es384 {
    use error_stack::Report;
    use no_way_jose_core::error::{JoseError, JoseResult};

    use super::{Es384, ecdsa};

    pub type SigningKey = no_way_jose_core::SigningKey<Es384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es384>;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn signing_key_from_sec1_der(bytes: &[u8]) -> JoseResult<SigningKey> {
        ecdsa::SigningKey::from_sec1_der(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
    pub fn verifying_key_from_x962(bytes: &[u8]) -> JoseResult<VerifyingKey> {
        ecdsa::VerifyingKey::from_x962_uncompressed(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }
}

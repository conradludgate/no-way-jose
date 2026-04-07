use error_stack::Report;
use graviola::signing::eddsa;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OkpCurve, OkpParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

/// `EdDSA`: Edwards-curve Digital Signature Algorithm using Ed25519 (graviola backend).
pub struct EdDsa;

impl JwsAlgorithm for EdDsa {
    const ALG: &'static str = "EdDSA";
}

impl HasKey<Signing> for EdDsa {
    type Key = eddsa::Ed25519SigningKey;
}

impl HasKey<Verifying> for EdDsa {
    type Key = eddsa::Ed25519VerifyingKey;
}

impl Signer for EdDsa {
    fn sign(key: &eddsa::Ed25519SigningKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
        Ok(key.sign(signing_input).to_vec())
    }
}

impl Verifier for EdDsa {
    fn verify(
        key: &eddsa::Ed25519VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> JoseResult<()> {
        key.verify(signature, signing_input)
            .map_err(|_| Report::new(JoseError::CryptoError))
    }
}

impl JwkKeyConvert<Signing> for EdDsa {
    fn key_to_jwk(key: &eddsa::Ed25519SigningKey) -> Jwk {
        Jwk {
            kid: None,
            alg: Some("EdDSA".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Okp(OkpParams {
                crv: OkpCurve::Ed25519,
                x: key.public_key().as_bytes().to_vec(),
                d: Some(key.as_seed().to_vec()),
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<eddsa::Ed25519SigningKey> {
        validate_okp_jwk(jwk)?;
        match &jwk.key {
            JwkParams::Okp(p) => {
                let d =
                    p.d.as_ref()
                        .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                eddsa::Ed25519SigningKey::from_bytes(d)
                    .map_err(|_| Report::new(JoseError::InvalidKey))
            }
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

impl JwkKeyConvert<Verifying> for EdDsa {
    fn key_to_jwk(key: &eddsa::Ed25519VerifyingKey) -> Jwk {
        Jwk {
            kid: None,
            alg: Some("EdDSA".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Okp(OkpParams {
                crv: OkpCurve::Ed25519,
                x: key.as_bytes().to_vec(),
                d: None,
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<eddsa::Ed25519VerifyingKey> {
        validate_okp_jwk(jwk)?;
        match &jwk.key {
            JwkParams::Okp(p) => eddsa::Ed25519VerifyingKey::from_bytes(&p.x)
                .map_err(|_| Report::new(JoseError::InvalidKey)),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

fn validate_okp_jwk(jwk: &Jwk) -> JoseResult<()> {
    if let Some(alg) = &jwk.alg
        && alg != "EdDSA"
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Okp(p) if p.crv == OkpCurve::Ed25519 => Ok(()),
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

pub type SigningKey = no_way_jose_core::SigningKey<EdDsa>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<EdDsa>;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_bytes(bytes: &[u8]) -> JoseResult<SigningKey> {
    eddsa::Ed25519SigningKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> JoseResult<VerifyingKey> {
    eddsa::Ed25519VerifyingKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(key.inner().public_key())
}

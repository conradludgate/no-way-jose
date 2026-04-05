use graviola::signing::eddsa;
use no_way_jose_core::JoseError;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OkpParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

/// `EdDSA`: Edwards-curve Digital Signature Algorithm using Ed25519 (graviola backend).
pub struct EdDsa;

impl no_way_jose_core::__private::Sealed for EdDsa {}

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
    fn sign(key: &eddsa::Ed25519SigningKey, signing_input: &[u8]) -> Result<Vec<u8>, JoseError> {
        Ok(key.sign(signing_input).to_vec())
    }
}

impl Verifier for EdDsa {
    fn verify(
        key: &eddsa::Ed25519VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> Result<(), JoseError> {
        key.verify(signature, signing_input)
            .map_err(|_| JoseError::CryptoError)
    }
}

impl JwkKeyConvert<Signing> for EdDsa {
    fn key_to_jwk(key: &eddsa::Ed25519SigningKey) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            kid: None,
            alg: Some("EdDSA".into()),
            use_: None,
            key_ops: None,
            params: JwkParams::Okp(OkpParams {
                crv: "Ed25519".into(),
                x: key.public_key().as_bytes().to_vec(),
                d: Some(key.as_seed().to_vec()),
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> Result<eddsa::Ed25519SigningKey, JoseError> {
        validate_okp_jwk(jwk)?;
        match &jwk.params {
            JwkParams::Okp(p) => {
                let d = p.d.as_ref().ok_or(JoseError::InvalidKey)?;
                eddsa::Ed25519SigningKey::from_bytes(d).map_err(|_| JoseError::InvalidKey)
            }
            _ => Err(JoseError::InvalidKey),
        }
    }
}

impl JwkKeyConvert<Verifying> for EdDsa {
    fn key_to_jwk(key: &eddsa::Ed25519VerifyingKey) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            kid: None,
            alg: Some("EdDSA".into()),
            use_: None,
            key_ops: None,
            params: JwkParams::Okp(OkpParams {
                crv: "Ed25519".into(),
                x: key.as_bytes().to_vec(),
                d: None,
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> Result<eddsa::Ed25519VerifyingKey, JoseError> {
        validate_okp_jwk(jwk)?;
        match &jwk.params {
            JwkParams::Okp(p) => {
                eddsa::Ed25519VerifyingKey::from_bytes(&p.x).map_err(|_| JoseError::InvalidKey)
            }
            _ => Err(JoseError::InvalidKey),
        }
    }
}

fn validate_okp_jwk(jwk: &Jwk) -> Result<(), JoseError> {
    if jwk.kty != "OKP" {
        return Err(JoseError::InvalidKey);
    }
    if let Some(alg) = &jwk.alg
        && alg != "EdDSA"
    {
        return Err(JoseError::InvalidKey);
    }
    match &jwk.params {
        JwkParams::Okp(p) if p.crv == "Ed25519" => Ok(()),
        _ => Err(JoseError::InvalidKey),
    }
}

pub type SigningKey = no_way_jose_core::SigningKey<EdDsa>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<EdDsa>;

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, JoseError> {
    eddsa::Ed25519SigningKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, JoseError> {
    eddsa::Ed25519VerifyingKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| JoseError::InvalidKey)
}

#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(key.inner().public_key())
}

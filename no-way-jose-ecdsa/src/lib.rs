//! ECDSA-based JWS algorithms: [`Es256`] (P-256), [`Es384`] (P-384), and [`Es512`] (P-521).
//!
//! ECDSA is an asymmetric algorithm -- a private key signs and the
//! corresponding public key verifies. Keys can be constructed from raw scalar
//! bytes ([`signing_key_from_bytes`]) or SEC1-encoded public keys
//! ([`verifying_key_from_sec1`]).
//!
//! The root-level key functions target ES256. For ES384 and ES512 use the
//! [`es384`] and [`es512`] submodules respectively.

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::vec::Vec;

use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{EcCurve, EcParams, Jwk, JwkKeyConvert, JwkParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

// -- ES256 --

/// ES256: ECDSA using P-256 and SHA-256 (RFC 7518 Section 3.4).
pub struct Es256;

impl JwsAlgorithm for Es256 {
    const ALG: &'static str = "ES256";
}

impl HasKey<Signing> for Es256 {
    type Key = p256::ecdsa::SigningKey;
}

impl HasKey<Verifying> for Es256 {
    type Key = p256::ecdsa::VerifyingKey;
}

impl Signer for Es256 {
    fn sign(key: &p256::ecdsa::SigningKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for Es256 {
    fn verify(
        key: &p256::ecdsa::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> JoseResult<()> {
        use p256::ecdsa::signature::Verifier;
        let sig = p256::ecdsa::Signature::from_slice(signature)
            .map_err(|_| Report::new(JoseError::CryptoError))?;
        key.verify(signing_input, &sig)
            .map_err(|_| Report::new(JoseError::CryptoError))
    }
}

impl JwkKeyConvert<Signing> for Es256 {
    fn key_to_jwk(key: &p256::ecdsa::SigningKey) -> Jwk {
        let vk = key.verifying_key();
        let point = vk.to_sec1_point(false);
        Jwk {
            kid: None,
            alg: Some("ES256".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P256,
                x: point.x().unwrap().to_vec(),
                y: point.y().unwrap().to_vec(),
                d: Some(key.to_bytes().to_vec()),
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<p256::ecdsa::SigningKey> {
        validate_ec_jwk(jwk, "ES256", EcCurve::P256)?;
        match &jwk.key {
            JwkParams::Ec(p) => {
                let d =
                    p.d.as_ref()
                        .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                p256::ecdsa::SigningKey::from_slice(d)
                    .map_err(|_| Report::new(JoseError::InvalidKey))
            }
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

impl JwkKeyConvert<Verifying> for Es256 {
    fn key_to_jwk(key: &p256::ecdsa::VerifyingKey) -> Jwk {
        let point = key.to_sec1_point(false);
        Jwk {
            kid: None,
            alg: Some("ES256".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P256,
                x: point.x().unwrap().to_vec(),
                y: point.y().unwrap().to_vec(),
                d: None,
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<p256::ecdsa::VerifyingKey> {
        validate_ec_jwk(jwk, "ES256", EcCurve::P256)?;
        match &jwk.key {
            JwkParams::Ec(p) => p256_verifying_key_from_xy(&p.x, &p.y),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

/// ES256 signing key.
pub type SigningKey = no_way_jose_core::SigningKey<Es256>;
/// ES256 verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Es256>;

/// Create an ES256 signing key from a raw P-256 scalar (32 bytes).
///
/// # Errors
/// Returns `JoseError::InvalidKey` if the scalar bytes are invalid.
pub fn signing_key_from_bytes(bytes: &[u8]) -> JoseResult<SigningKey> {
    p256::ecdsa::SigningKey::from_slice(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// Create an ES256 verifying key from SEC1-encoded public key bytes.
///
/// # Errors
/// Returns `JoseError::InvalidKey` if the SEC1 bytes are invalid.
pub fn verifying_key_from_sec1(bytes: &[u8]) -> JoseResult<VerifyingKey> {
    p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// Derive the ES256 verifying key from a signing key.
#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(*key.inner().verifying_key())
}

// -- ES384 --

/// ES384: ECDSA using P-384 and SHA-384 (RFC 7518 Section 3.4).
pub struct Es384;

impl JwsAlgorithm for Es384 {
    const ALG: &'static str = "ES384";
}

impl HasKey<Signing> for Es384 {
    type Key = p384::ecdsa::SigningKey;
}

impl HasKey<Verifying> for Es384 {
    type Key = p384::ecdsa::VerifyingKey;
}

impl Signer for Es384 {
    fn sign(key: &p384::ecdsa::SigningKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
        use p384::ecdsa::signature::Signer;
        let sig: p384::ecdsa::Signature = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for Es384 {
    fn verify(
        key: &p384::ecdsa::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> JoseResult<()> {
        use p384::ecdsa::signature::Verifier;
        let sig = p384::ecdsa::Signature::from_slice(signature)
            .map_err(|_| Report::new(JoseError::CryptoError))?;
        key.verify(signing_input, &sig)
            .map_err(|_| Report::new(JoseError::CryptoError))
    }
}

impl JwkKeyConvert<Signing> for Es384 {
    fn key_to_jwk(key: &p384::ecdsa::SigningKey) -> Jwk {
        let vk = key.verifying_key();
        let point = vk.to_sec1_point(false);
        Jwk {
            kid: None,
            alg: Some("ES384".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P384,
                x: point.x().unwrap().to_vec(),
                y: point.y().unwrap().to_vec(),
                d: Some(key.to_bytes().to_vec()),
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<p384::ecdsa::SigningKey> {
        validate_ec_jwk(jwk, "ES384", EcCurve::P384)?;
        match &jwk.key {
            JwkParams::Ec(p) => {
                let d =
                    p.d.as_ref()
                        .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                p384::ecdsa::SigningKey::from_slice(d)
                    .map_err(|_| Report::new(JoseError::InvalidKey))
            }
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

impl JwkKeyConvert<Verifying> for Es384 {
    fn key_to_jwk(key: &p384::ecdsa::VerifyingKey) -> Jwk {
        let point = key.to_sec1_point(false);
        Jwk {
            kid: None,
            alg: Some("ES384".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P384,
                x: point.x().unwrap().to_vec(),
                y: point.y().unwrap().to_vec(),
                d: None,
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<p384::ecdsa::VerifyingKey> {
        validate_ec_jwk(jwk, "ES384", EcCurve::P384)?;
        match &jwk.key {
            JwkParams::Ec(p) => p384_verifying_key_from_xy(&p.x, &p.y),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

// -- ES512 --

/// ES512: ECDSA using P-521 and SHA-512 (RFC 7518 Section 3.4).
pub struct Es512;

impl JwsAlgorithm for Es512 {
    const ALG: &'static str = "ES512";
}

impl HasKey<Signing> for Es512 {
    type Key = p521::ecdsa::SigningKey;
}

impl HasKey<Verifying> for Es512 {
    type Key = p521::ecdsa::VerifyingKey;
}

impl Signer for Es512 {
    fn sign(key: &p521::ecdsa::SigningKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
        use p521::ecdsa::signature::Signer;
        let sig: p521::ecdsa::Signature = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for Es512 {
    fn verify(
        key: &p521::ecdsa::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> JoseResult<()> {
        use p521::ecdsa::signature::Verifier;
        let sig = p521::ecdsa::Signature::from_slice(signature)
            .map_err(|_| Report::new(JoseError::CryptoError))?;
        key.verify(signing_input, &sig)
            .map_err(|_| Report::new(JoseError::CryptoError))
    }
}

impl JwkKeyConvert<Signing> for Es512 {
    fn key_to_jwk(key: &p521::ecdsa::SigningKey) -> Jwk {
        let vk = key.verifying_key();
        let point = vk.to_sec1_point(false);
        Jwk {
            kid: None,
            alg: Some("ES512".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P521,
                x: point.x().unwrap().to_vec(),
                y: point.y().unwrap().to_vec(),
                d: Some(key.to_bytes().to_vec()),
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<p521::ecdsa::SigningKey> {
        validate_ec_jwk(jwk, "ES512", EcCurve::P521)?;
        match &jwk.key {
            JwkParams::Ec(p) => {
                let d =
                    p.d.as_ref()
                        .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                p521::ecdsa::SigningKey::from_slice(d)
                    .map_err(|_| Report::new(JoseError::InvalidKey))
            }
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

impl JwkKeyConvert<Verifying> for Es512 {
    fn key_to_jwk(key: &p521::ecdsa::VerifyingKey) -> Jwk {
        let point = key.to_sec1_point(false);
        Jwk {
            kid: None,
            alg: Some("ES512".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P521,
                x: point.x().unwrap().to_vec(),
                y: point.y().unwrap().to_vec(),
                d: None,
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<p521::ecdsa::VerifyingKey> {
        validate_ec_jwk(jwk, "ES512", EcCurve::P521)?;
        match &jwk.key {
            JwkParams::Ec(p) => p521_verifying_key_from_xy(&p.x, &p.y),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
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

fn p256_verifying_key_from_xy(x: &[u8], y: &[u8]) -> JoseResult<p256::ecdsa::VerifyingKey> {
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

fn p384_verifying_key_from_xy(x: &[u8], y: &[u8]) -> JoseResult<p384::ecdsa::VerifyingKey> {
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

fn p521_verifying_key_from_xy(x: &[u8], y: &[u8]) -> JoseResult<p521::ecdsa::VerifyingKey> {
    let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

pub mod es384 {
    use error_stack::Report;
    use no_way_jose_core::error::{JoseError, JoseResult};

    pub type SigningKey = no_way_jose_core::SigningKey<super::Es384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Es384>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the scalar bytes are invalid.
    pub fn signing_key_from_bytes(bytes: &[u8]) -> JoseResult<SigningKey> {
        p384::ecdsa::SigningKey::from_slice(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the SEC1 bytes are invalid.
    pub fn verifying_key_from_sec1(bytes: &[u8]) -> JoseResult<VerifyingKey> {
        p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(*key.inner().verifying_key())
    }
}

pub mod es512 {
    use error_stack::Report;
    use no_way_jose_core::error::{JoseError, JoseResult};

    pub type SigningKey = no_way_jose_core::SigningKey<super::Es512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Es512>;

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the scalar bytes are invalid.
    pub fn signing_key_from_bytes(bytes: &[u8]) -> JoseResult<SigningKey> {
        p521::ecdsa::SigningKey::from_slice(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    /// # Errors
    /// Returns `JoseError::InvalidKey` if the SEC1 bytes are invalid.
    pub fn verifying_key_from_sec1(bytes: &[u8]) -> JoseResult<VerifyingKey> {
        p521::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
            .map(no_way_jose_core::key::Key::new)
            .map_err(|_| Report::new(JoseError::InvalidKey))
    }

    #[must_use]
    pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
        no_way_jose_core::key::Key::new(*key.inner().verifying_key())
    }
}

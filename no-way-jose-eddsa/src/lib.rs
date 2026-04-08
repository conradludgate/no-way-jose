//! EdDSA JWS algorithm using Ed25519 ([`EdDsa`]).
//!
//! ## Algorithm
//!
//! | JWS `alg` | Curve | Private / public key | Signature | Specification |
//! |-----------|-------|----------------------|-----------|---------------|
//! | EdDSA | Ed25519 (OKP) | 32 bytes each | 64 bytes | [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) |
//!
//! EdDSA is asymmetric: [`signing_key`] generates a random signing key; [`verifying_key_from_signing`]
//! derives the public key. Keys can also be built from 32-byte seeds ([`signing_key_from_bytes`]) or
//! raw public bytes ([`verifying_key_from_bytes`]).
//!
//! ## Example
//!
//! ```
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::validation::NoValidation;
//! use no_way_jose_core::{CompactJws, UnsignedToken};
//! use no_way_jose_eddsa::EdDsa;
//!
//! let sk = no_way_jose_eddsa::signing_key();
//! let vk = no_way_jose_eddsa::verifying_key_from_signing(&sk);
//!
//! let payload = r#"{"sub":"alice"}"#;
//! let claims = RawJson(payload.into());
//! let token_str = UnsignedToken::<EdDsa, _>::new(claims)
//!     .sign(&sk)
//!     .unwrap()
//!     .to_string();
//!
//! let token: CompactJws<EdDsa> = token_str.parse().unwrap();
//! let verified = token
//!     .verify(&vk, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(verified.claims.0, payload);
//! ```
//!
//! See also [no-way-jose-core](https://docs.rs/no-way-jose-core) and
//! [no-way-jose-claims](https://docs.rs/no-way-jose-claims).

#![no_std]
#![warn(clippy::pedantic)]

extern crate alloc;

use alloc::vec::Vec;

use error_stack::Report;
pub use no_way_jose_core;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, OkpCurve, OkpParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

/// `EdDSA`: Edwards-curve Digital Signature Algorithm using Ed25519 (RFC 8037).
pub struct EdDsa;

impl JwsAlgorithm for EdDsa {
    const ALG: &'static str = "EdDSA";
}

impl HasKey<Signing> for EdDsa {
    type Key = ed25519_dalek::SigningKey;
}

impl HasKey<Verifying> for EdDsa {
    type Key = ed25519_dalek::VerifyingKey;
}

impl Signer for EdDsa {
    fn sign(key: &ed25519_dalek::SigningKey, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
        use ed25519_dalek::Signer;
        let sig = key.sign(signing_input);
        Ok(sig.to_bytes().to_vec())
    }
}

impl Verifier for EdDsa {
    fn verify(
        key: &ed25519_dalek::VerifyingKey,
        signing_input: &[u8],
        signature: &[u8],
    ) -> JoseResult<()> {
        use ed25519_dalek::Verifier;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| Report::new(JoseError::CryptoError))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        key.verify(signing_input, &sig)
            .map_err(|_| Report::new(JoseError::CryptoError))
    }
}

impl JwkKeyConvert<Signing> for EdDsa {
    fn key_to_jwk(key: &ed25519_dalek::SigningKey) -> Jwk {
        Jwk {
            kid: None,
            alg: Some("EdDSA".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Okp(OkpParams {
                crv: OkpCurve::Ed25519,
                x: key.verifying_key().to_bytes().to_vec(),
                d: Some(key.to_bytes().to_vec()),
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<ed25519_dalek::SigningKey> {
        validate_okp_jwk(jwk)?;
        match &jwk.key {
            JwkParams::Okp(p) => {
                let d =
                    p.d.as_ref()
                        .ok_or_else(|| Report::new(JoseError::InvalidKey))?;
                let bytes: [u8; 32] = d
                    .as_slice()
                    .try_into()
                    .map_err(|_| Report::new(JoseError::InvalidKey))?;
                Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
            }
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

impl JwkKeyConvert<Verifying> for EdDsa {
    fn key_to_jwk(key: &ed25519_dalek::VerifyingKey) -> Jwk {
        Jwk {
            kid: None,
            alg: Some("EdDSA".into()),
            use_: None,
            key_ops: None,
            key: JwkParams::Okp(OkpParams {
                crv: OkpCurve::Ed25519,
                x: key.to_bytes().to_vec(),
                d: None,
            }),
        }
    }

    fn key_from_jwk(jwk: &Jwk) -> JoseResult<ed25519_dalek::VerifyingKey> {
        validate_okp_jwk(jwk)?;
        match &jwk.key {
            JwkParams::Okp(p) => {
                let bytes: [u8; 32] =
                    p.x.as_slice()
                        .try_into()
                        .map_err(|_| Report::new(JoseError::InvalidKey))?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| Report::new(JoseError::InvalidKey))
            }
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

/// `EdDSA` signing key.
pub type SigningKey = no_way_jose_core::SigningKey<EdDsa>;
/// `EdDSA` verifying key.
pub type VerifyingKey = no_way_jose_core::VerifyingKey<EdDsa>;

/// Create a random `EdDSA` signing key using OS randomness.
#[must_use]
pub fn signing_key() -> SigningKey {
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    no_way_jose_core::key::Key::new(ed25519_dalek::SigningKey::generate(&mut rng))
}

/// Create an `EdDSA` signing key from a 32-byte Ed25519 seed.
#[must_use]
pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    no_way_jose_core::key::Key::new(ed25519_dalek::SigningKey::from_bytes(bytes))
}

/// Create an `EdDSA` verifying key from 32-byte Ed25519 public key bytes.
///
/// # Errors
/// Returns `JoseError::InvalidKey` if the public key bytes are invalid.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> JoseResult<VerifyingKey> {
    ed25519_dalek::VerifyingKey::from_bytes(bytes)
        .map(no_way_jose_core::key::Key::new)
        .map_err(|_| Report::new(JoseError::InvalidKey))
}

/// Derive the `EdDSA` verifying key from a signing key.
#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(key.inner().verifying_key())
}

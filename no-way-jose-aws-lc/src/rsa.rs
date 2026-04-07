use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, KeyPair, RsaKeyPair, UnparsedPublicKey};
use error_stack::Report;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

pub struct RsaVerifyingKey {
    pub(crate) bytes: Vec<u8>,
}

impl RsaVerifyingKey {
    /// Wrap raw DER-encoded RSA public key bytes for verification.
    #[must_use]
    pub fn from_der(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

macro_rules! rsa_algorithm {
    (
        $name:ident, $alg:literal,
        $sign_encoding:expr, $verify_alg:expr,
        $doc:literal
    ) => {
        #[doc = $doc]
        pub struct $name;

        impl JwsAlgorithm for $name {
            const ALG: &'static str = $alg;
        }

        impl HasKey<Signing> for $name {
            type Key = RsaKeyPair;
        }

        impl HasKey<Verifying> for $name {
            type Key = RsaVerifyingKey;
        }

        impl Signer for $name {
            fn sign(key: &RsaKeyPair, signing_input: &[u8]) -> JoseResult<Vec<u8>> {
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; key.public_modulus_len()];
                key.sign($sign_encoding, &rng, signing_input, &mut sig)
                    .map_err(|_| Report::new(JoseError::CryptoError))?;
                Ok(sig)
            }
        }

        impl Verifier for $name {
            fn verify(
                key: &RsaVerifyingKey,
                signing_input: &[u8],
                sig: &[u8],
            ) -> JoseResult<()> {
                let pk = UnparsedPublicKey::new($verify_alg, &key.bytes);
                pk.verify(signing_input, sig)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }
    };
}

rsa_algorithm!(Rs256, "RS256", &signature::RSA_PKCS1_SHA256, &signature::RSA_PKCS1_2048_8192_SHA256,
    "RS256: RSASSA-PKCS1-v1_5 using SHA-256 (aws-lc-rs backend).");
rsa_algorithm!(Rs384, "RS384", &signature::RSA_PKCS1_SHA384, &signature::RSA_PKCS1_2048_8192_SHA384,
    "RS384: RSASSA-PKCS1-v1_5 using SHA-384 (aws-lc-rs backend).");
rsa_algorithm!(Rs512, "RS512", &signature::RSA_PKCS1_SHA512, &signature::RSA_PKCS1_2048_8192_SHA512,
    "RS512: RSASSA-PKCS1-v1_5 using SHA-512 (aws-lc-rs backend).");
rsa_algorithm!(Ps256, "PS256", &signature::RSA_PSS_SHA256, &signature::RSA_PSS_2048_8192_SHA256,
    "PS256: RSASSA-PSS using SHA-256 (aws-lc-rs backend).");
rsa_algorithm!(Ps384, "PS384", &signature::RSA_PSS_SHA384, &signature::RSA_PSS_2048_8192_SHA384,
    "PS384: RSASSA-PSS using SHA-384 (aws-lc-rs backend).");
rsa_algorithm!(Ps512, "PS512", &signature::RSA_PSS_SHA512, &signature::RSA_PSS_2048_8192_SHA512,
    "PS512: RSASSA-PSS using SHA-512 (aws-lc-rs backend).");

fn make_signing_key(der: &[u8]) -> JoseResult<RsaKeyPair> {
    RsaKeyPair::from_der(der).map_err(|_| Report::new(JoseError::InvalidKey))
}

pub type SigningKey = no_way_jose_core::SigningKey<Rs256>;
pub type VerifyingKey = no_way_jose_core::VerifyingKey<Rs256>;

/// Create an RS256 signing key from DER-encoded RSA private key (PKCS#1 or PKCS#8).
///
/// # Errors
/// Returns [`JoseError::InvalidKey`] if the key bytes are invalid.
pub fn signing_key_from_der(bytes: &[u8]) -> JoseResult<SigningKey> {
    make_signing_key(bytes).map(no_way_jose_core::key::Key::new)
}

/// Create an RS256 verifying key from DER-encoded RSA public key.
#[must_use]
pub fn verifying_key_from_der(bytes: &[u8]) -> VerifyingKey {
    no_way_jose_core::key::Key::new(RsaVerifyingKey {
        bytes: bytes.to_vec(),
    })
}

/// Extract the public key bytes from a signing key pair.
#[must_use]
pub fn verifying_key_from_signing(key: &SigningKey) -> VerifyingKey {
    no_way_jose_core::key::Key::new(RsaVerifyingKey {
        bytes: key.inner().public_key().as_ref().to_vec(),
    })
}

pub mod rs384 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Rs384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Rs384>;
}

pub mod rs512 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Rs512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Rs512>;
}

pub mod ps256 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps256>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps256>;
}

pub mod ps384 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps384>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps384>;
}

pub mod ps512 {
    pub type SigningKey = no_way_jose_core::SigningKey<super::Ps512>;
    pub type VerifyingKey = no_way_jose_core::VerifyingKey<super::Ps512>;
}

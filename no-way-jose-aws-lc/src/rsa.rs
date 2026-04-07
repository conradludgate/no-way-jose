use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, KeyPair, RsaKeyPair, UnparsedPublicKey};
use error_stack::Report;
use no_way_jose_core::algorithm::{JwsAlgorithm, Signer, Verifier};
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::jwk::{Jwk, JwkKeyConvert, JwkParams, RsaParams};
use no_way_jose_core::key::{HasKey, Signing, Verifying};

pub struct RsaVerifyingKey {
    bytes: Vec<u8>,
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
            fn verify(key: &RsaVerifyingKey, signing_input: &[u8], sig: &[u8]) -> JoseResult<()> {
                let pk = UnparsedPublicKey::new($verify_alg, &key.bytes);
                pk.verify(signing_input, sig)
                    .map_err(|_| Report::new(JoseError::CryptoError))
            }
        }

        impl JwkKeyConvert<Verifying> for $name {
            fn key_to_jwk(key: &RsaVerifyingKey) -> Jwk {
                rsa_vk_to_jwk(key, $alg)
            }

            fn key_from_jwk(jwk: &Jwk) -> JoseResult<RsaVerifyingKey> {
                rsa_vk_from_jwk(jwk, $alg)
            }
        }
    };
}

fn rsa_vk_to_jwk(key: &RsaVerifyingKey, alg: &str) -> Jwk {
    let (n, e) = parse_rsa_public_key_der(&key.bytes).expect("valid RSA public key DER");
    Jwk {
        kid: None,
        alg: Some(alg.into()),
        use_: None,
        key_ops: None,
        key: JwkParams::Rsa(RsaParams { n, e, prv: None }),
    }
}

fn rsa_vk_from_jwk(jwk: &Jwk, expected_alg: &str) -> JoseResult<RsaVerifyingKey> {
    if let Some(alg) = &jwk.alg
        && alg != expected_alg
    {
        return Err(Report::new(JoseError::InvalidKey));
    }
    match &jwk.key {
        JwkParams::Rsa(p) => {
            let der = encode_rsa_public_key_der(&p.n, &p.e);
            Ok(RsaVerifyingKey { bytes: der })
        }
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

// -- Minimal ASN.1 DER codec for PKCS#1 RSAPublicKey --

fn parse_rsa_public_key_der(input: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (inner, rest) = read_der_sequence(input)?;
    if !rest.is_empty() {
        return None;
    }
    let (n_raw, rest) = read_der_integer(inner)?;
    let (e_raw, rest) = read_der_integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    Some((
        strip_leading_zeros(n_raw).to_vec(),
        strip_leading_zeros(e_raw).to_vec(),
    ))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn read_der_tag(input: &[u8], expected: u8) -> Option<(&[u8], &[u8])> {
    if input.first()? != &expected {
        return None;
    }
    read_der_length(&input[1..])
}

fn read_der_sequence(input: &[u8]) -> Option<(&[u8], &[u8])> {
    read_der_tag(input, 0x30)
}

fn read_der_integer(input: &[u8]) -> Option<(&[u8], &[u8])> {
    read_der_tag(input, 0x02)
}

fn read_der_length(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *input.first()?;
    if first < 0x80 {
        let len = first as usize;
        if input.len() < 1 + len {
            return None;
        }
        Some((&input[1..=len], &input[1 + len..]))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || input.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for &b in &input[1..=num_bytes] {
            len = len.checked_shl(8)? | (b as usize);
        }
        let offset = 1 + num_bytes;
        if input.len() < offset + len {
            return None;
        }
        Some((&input[offset..offset + len], &input[offset + len..]))
    }
}

fn encode_rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let n_int = encode_der_integer(n);
    let e_int = encode_der_integer(e);
    let inner_len = n_int.len() + e_int.len();

    let mut out = Vec::with_capacity(1 + 4 + inner_len);
    out.push(0x30);
    encode_der_length(&mut out, inner_len);
    out.extend_from_slice(&n_int);
    out.extend_from_slice(&e_int);
    out
}

fn encode_der_integer(value: &[u8]) -> Vec<u8> {
    let value = strip_leading_zeros(value);
    let needs_pad = value.first().is_some_and(|&b| b & 0x80 != 0);
    let content_len = if needs_pad {
        value.len() + 1
    } else {
        value.len()
    };

    let mut out = Vec::with_capacity(1 + 4 + content_len);
    out.push(0x02);
    encode_der_length(&mut out, content_len);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(value);
    out
}

#[allow(clippy::cast_possible_truncation)]
fn encode_der_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else if len <= 0xFFFF {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

rsa_algorithm!(
    Rs256,
    "RS256",
    &signature::RSA_PKCS1_SHA256,
    &signature::RSA_PKCS1_2048_8192_SHA256,
    "RS256: RSASSA-PKCS1-v1_5 using SHA-256 (aws-lc-rs backend)."
);
rsa_algorithm!(
    Rs384,
    "RS384",
    &signature::RSA_PKCS1_SHA384,
    &signature::RSA_PKCS1_2048_8192_SHA384,
    "RS384: RSASSA-PKCS1-v1_5 using SHA-384 (aws-lc-rs backend)."
);
rsa_algorithm!(
    Rs512,
    "RS512",
    &signature::RSA_PKCS1_SHA512,
    &signature::RSA_PKCS1_2048_8192_SHA512,
    "RS512: RSASSA-PKCS1-v1_5 using SHA-512 (aws-lc-rs backend)."
);
rsa_algorithm!(
    Ps256,
    "PS256",
    &signature::RSA_PSS_SHA256,
    &signature::RSA_PSS_2048_8192_SHA256,
    "PS256: RSASSA-PSS using SHA-256 (aws-lc-rs backend)."
);
rsa_algorithm!(
    Ps384,
    "PS384",
    &signature::RSA_PSS_SHA384,
    &signature::RSA_PSS_2048_8192_SHA384,
    "PS384: RSASSA-PSS using SHA-384 (aws-lc-rs backend)."
);
rsa_algorithm!(
    Ps512,
    "PS512",
    &signature::RSA_PSS_SHA512,
    &signature::RSA_PSS_2048_8192_SHA512,
    "PS512: RSASSA-PSS using SHA-512 (aws-lc-rs backend)."
);

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

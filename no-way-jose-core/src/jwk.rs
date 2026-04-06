//! JSON Web Key ([RFC 7517]) types and JWK Thumbprint ([RFC 7638]).
//!
//! A [`Jwk`] represents a single cryptographic key in the standard JSON format
//! used for interoperability across JOSE libraries and key distribution
//! endpoints (e.g. `/.well-known/jwks.json`). A [`JwkSet`] holds a collection
//! of keys and supports lookup by Key ID ([`JwkSet::find_by_kid`]).
//!
//! Key-type-specific parameters are stored in [`JwkParams`] variants:
//! [`EcParams`] (P-256, P-384, P-521), [`RsaParams`], [`OctParams`]
//! (symmetric), and [`OkpParams`] (Ed25519, X25519).
//!
//! ## Converting keys
//!
//! Algorithm crates implement [`JwkKeyConvert`] so that typed
//! [`Key`](crate::key::Key) values automatically gain [`ToJwk`] and [`FromJwk`]:
//!
//! ```ignore
//! let jwk: Jwk = signing_key.to_jwk();
//! let vk: VerifyingKey<Es256> = FromJwk::from_jwk(&jwk)?;
//! ```
//!
//! ## Thumbprints
//!
//! [`Jwk::thumbprint_canonical_json`] returns the deterministic JSON form
//! defined by RFC 7638 §3. Hash the result (e.g. with SHA-256) to produce a
//! stable key identifier.
//!
//! [RFC 7517]: https://datatracker.ietf.org/doc/html/rfc7517
//! [RFC 7638]: https://datatracker.ietf.org/doc/html/rfc7638

use alloc::string::String;
use alloc::vec::Vec;

use error_stack::{Report, ResultExt};

use crate::base64url;
use crate::error::{JoseError, JoseResult, JsonError};
use crate::json::{JsonReader, JsonWriter};

/// Intended use of a public key (RFC 7517 §4.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyUse {
    Sig,
    Enc,
}

/// Key operation (RFC 7517 §4.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyOp {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
}

impl KeyOp {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::WrapKey => "wrapKey",
            Self::UnwrapKey => "unwrapKey",
            Self::DeriveKey => "deriveKey",
            Self::DeriveBits => "deriveBits",
        }
    }

    fn from_str(s: &str) -> JoseResult<Self> {
        match s {
            "sign" => Ok(Self::Sign),
            "verify" => Ok(Self::Verify),
            "encrypt" => Ok(Self::Encrypt),
            "decrypt" => Ok(Self::Decrypt),
            "wrapKey" => Ok(Self::WrapKey),
            "unwrapKey" => Ok(Self::UnwrapKey),
            "deriveKey" => Ok(Self::DeriveKey),
            "deriveBits" => Ok(Self::DeriveBits),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

/// Elliptic curve identifier for `kty: "EC"` keys (RFC 7518 §6.2.1.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcCurve {
    P256,
    P384,
    P521,
}

impl EcCurve {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    fn from_str(s: &str) -> JoseResult<Self> {
        match s {
            "P-256" => Ok(Self::P256),
            "P-384" => Ok(Self::P384),
            "P-521" => Ok(Self::P521),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

/// Curve identifier for `kty: "OKP"` keys (RFC 8037 §2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OkpCurve {
    Ed25519,
    X25519,
}

impl OkpCurve {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
        }
    }

    fn from_str(s: &str) -> JoseResult<Self> {
        match s {
            "Ed25519" => Ok(Self::Ed25519),
            "X25519" => Ok(Self::X25519),
            _ => Err(Report::new(JoseError::InvalidKey)),
        }
    }
}

/// Key-type-specific parameters.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum JwkParams {
    Ec(EcParams),
    Rsa(RsaParams),
    Oct(OctParams),
    Okp(OkpParams),
}

/// Parameters for `kty: "EC"` keys (RFC 7518 §6.2).
#[derive(Clone, Debug)]
pub struct EcParams {
    pub crv: EcCurve,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    pub d: Option<Vec<u8>>,
}

/// Parameters for `kty: "RSA"` keys (RFC 7518 §6.3).
#[derive(Clone, Debug)]
pub struct RsaParams {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub prv: Option<RsaPrivateParams>,
}

/// RSA private key parameters (RFC 7518 §6.3.2).
#[derive(Clone, Debug)]
pub struct RsaPrivateParams {
    pub d: Vec<u8>,
    pub p: Option<Vec<u8>>,
    pub q: Option<Vec<u8>>,
    pub dp: Option<Vec<u8>>,
    pub dq: Option<Vec<u8>>,
    pub qi: Option<Vec<u8>>,
}

/// Parameters for `kty: "oct"` symmetric keys (RFC 7518 §6.4).
#[derive(Clone, Debug)]
pub struct OctParams {
    pub k: Vec<u8>,
}

/// Parameters for `kty: "OKP"` keys (RFC 8037 §2).
#[derive(Clone, Debug)]
pub struct OkpParams {
    pub crv: OkpCurve,
    pub x: Vec<u8>,
    pub d: Option<Vec<u8>>,
}

/// A parsed JSON Web Key (RFC 7517 §4).
#[derive(Clone, Debug)]
pub struct Jwk {
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub use_: Option<KeyUse>,
    pub key_ops: Option<Vec<KeyOp>>,
    pub key: JwkParams,
}

impl Jwk {
    /// Returns the key type string (`"EC"`, `"RSA"`, `"oct"`, or `"OKP"`).
    #[must_use]
    pub fn kty(&self) -> &'static str {
        match &self.key {
            JwkParams::Ec(_) => "EC",
            JwkParams::Rsa(_) => "RSA",
            JwkParams::Oct(_) => "oct",
            JwkParams::Okp(_) => "OKP",
        }
    }
}

/// A JSON Web Key Set (RFC 7517 §5).
#[derive(Clone, Debug)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    #[must_use]
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

/// Serialize a key to JWK form.
pub trait ToJwk {
    fn to_jwk(&self) -> Jwk;
}

/// Deserialize a key from JWK form.
pub trait FromJwk: Sized {
    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the JWK does not match this key type.
    fn from_jwk(jwk: &Jwk) -> JoseResult<Self>;
}

/// Algorithm-level JWK conversion. Implement this on algorithm ZSTs so
/// `Key<A, K>` automatically gains `ToJwk`/`FromJwk` via blanket impls.
pub trait JwkKeyConvert<K: crate::key::KeyPurpose>: crate::key::HasKey<K> {
    fn key_to_jwk(key: &<Self as crate::key::HasKey<K>>::Key) -> Jwk;

    /// # Errors
    /// Returns [`JoseError::InvalidKey`] if the JWK does not represent a valid key for this algorithm.
    fn key_from_jwk(jwk: &Jwk) -> JoseResult<<Self as crate::key::HasKey<K>>::Key>;
}

impl<A, K> ToJwk for crate::key::Key<A, K>
where
    A: JwkKeyConvert<K>,
    K: crate::key::KeyPurpose,
{
    fn to_jwk(&self) -> Jwk {
        A::key_to_jwk(self.inner())
    }
}

impl<A, K> FromJwk for crate::key::Key<A, K>
where
    A: JwkKeyConvert<K>,
    K: crate::key::KeyPurpose,
{
    fn from_jwk(jwk: &Jwk) -> JoseResult<Self> {
        A::key_from_jwk(jwk).map(crate::key::Key::new)
    }
}

// ====================================================================
// JSON serialization
// ====================================================================

impl Jwk {
    #[must_use]
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut w = JsonWriter::new();
        w.string("kty", self.kty());
        if let Some(kid) = &self.kid {
            w.string("kid", kid);
        }
        if let Some(alg) = &self.alg {
            w.string("alg", alg);
        }
        if let Some(use_) = &self.use_ {
            w.string(
                "use",
                match use_ {
                    KeyUse::Sig => "sig",
                    KeyUse::Enc => "enc",
                },
            );
        }
        if let Some(key_ops) = &self.key_ops {
            let strs: Vec<String> = key_ops.iter().map(|op| String::from(op.as_str())).collect();
            w.string_or_array("key_ops", &strs);
        }
        match &self.key {
            JwkParams::Ec(p) => {
                w.string("crv", p.crv.as_str());
                w.string("x", &base64url::encode(&p.x));
                w.string("y", &base64url::encode(&p.y));
                if let Some(d) = &p.d {
                    w.string("d", &base64url::encode(d));
                }
            }
            JwkParams::Rsa(p) => {
                w.string("n", &base64url::encode(&p.n));
                w.string("e", &base64url::encode(&p.e));
                if let Some(prv) = &p.prv {
                    w.string("d", &base64url::encode(&prv.d));
                    if let Some(p_val) = &prv.p {
                        w.string("p", &base64url::encode(p_val));
                    }
                    if let Some(q) = &prv.q {
                        w.string("q", &base64url::encode(q));
                    }
                    if let Some(dp) = &prv.dp {
                        w.string("dp", &base64url::encode(dp));
                    }
                    if let Some(dq) = &prv.dq {
                        w.string("dq", &base64url::encode(dq));
                    }
                    if let Some(qi) = &prv.qi {
                        w.string("qi", &base64url::encode(qi));
                    }
                }
            }
            JwkParams::Oct(p) => {
                w.string("k", &base64url::encode(&p.k));
            }
            JwkParams::Okp(p) => {
                w.string("crv", p.crv.as_str());
                w.string("x", &base64url::encode(&p.x));
                if let Some(d) = &p.d {
                    w.string("d", &base64url::encode(d));
                }
            }
        }
        w.finish()
    }

    /// # Errors
    /// Returns [`JoseError::MalformedToken`] or [`JoseError::InvalidKey`] on failure.
    #[allow(clippy::many_single_char_names)]
    pub fn from_json_bytes(bytes: &[u8]) -> JoseResult<Self> {
        let mut reader = JsonReader::new(bytes).change_context(JoseError::MalformedToken)?;

        let mut kty = None;
        let mut kid = None;
        let mut alg = None;
        let mut use_ = None;
        let mut key_ops_raw: Option<Vec<String>> = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        let mut d = None;
        let mut n = None;
        let mut e = None;
        let mut p = None;
        let mut q = None;
        let mut dp = None;
        let mut dq = None;
        let mut qi = None;
        let mut k = None;

        while let Some(field) = reader
            .next_key()
            .change_context(JoseError::MalformedToken)?
        {
            match field {
                "kty" => kty = Some(read_str_field(&mut reader)?),
                "kid" => kid = Some(read_str_field(&mut reader)?),
                "alg" => alg = Some(read_str_field(&mut reader)?),
                "use" => {
                    use_ = Some(match read_str_field(&mut reader)?.as_str() {
                        "sig" => KeyUse::Sig,
                        "enc" => KeyUse::Enc,
                        _ => return Err(Report::new(JoseError::InvalidKey)),
                    });
                }
                "key_ops" => {
                    key_ops_raw = Some(
                        reader
                            .read_string_array()
                            .change_context(JoseError::MalformedToken)?,
                    );
                }
                "crv" => crv = Some(read_str_field(&mut reader)?),
                "x" => x = Some(read_b64_string(&mut reader)?),
                "y" => y = Some(read_b64_string(&mut reader)?),
                "d" => d = Some(read_b64_string(&mut reader)?),
                "n" => n = Some(read_b64_string(&mut reader)?),
                "e" => e = Some(read_b64_string(&mut reader)?),
                "p" => p = Some(read_b64_string(&mut reader)?),
                "q" => q = Some(read_b64_string(&mut reader)?),
                "dp" => dp = Some(read_b64_string(&mut reader)?),
                "dq" => dq = Some(read_b64_string(&mut reader)?),
                "qi" => qi = Some(read_b64_string(&mut reader)?),
                "k" => k = Some(read_b64_string(&mut reader)?),
                _ => reader
                    .skip_value()
                    .change_context(JoseError::MalformedToken)?,
            }
        }

        let kty_str = kty
            .ok_or_else(|| Report::new(JsonError::MissingField))
            .change_context(JoseError::InvalidKey)?;
        let key = build_jwk_params(&kty_str, crv, x, y, d, n, e, p, q, dp, dq, qi, k)?;

        let key_ops = key_ops_raw
            .map(|ops| {
                ops.iter()
                    .map(|s| KeyOp::from_str(s))
                    .collect::<JoseResult<Vec<_>>>()
            })
            .transpose()?;

        Ok(Jwk {
            kid,
            alg,
            use_,
            key_ops,
            key,
        })
    }
}

#[allow(clippy::too_many_arguments, clippy::many_single_char_names)]
fn build_jwk_params(
    kty: &str,
    crv: Option<String>,
    x: Option<Vec<u8>>,
    y: Option<Vec<u8>>,
    d: Option<Vec<u8>>,
    n: Option<Vec<u8>>,
    e: Option<Vec<u8>>,
    p: Option<Vec<u8>>,
    q: Option<Vec<u8>>,
    dp: Option<Vec<u8>>,
    dq: Option<Vec<u8>>,
    qi: Option<Vec<u8>>,
    k: Option<Vec<u8>>,
) -> JoseResult<JwkParams> {
    fn required<T>(v: Option<T>) -> JoseResult<T> {
        v.ok_or_else(|| Report::new(JsonError::MissingField))
            .change_context(JoseError::InvalidKey)
    }

    match kty {
        "EC" => {
            let crv_str = required(crv)?;
            Ok(JwkParams::Ec(EcParams {
                crv: EcCurve::from_str(&crv_str)?,
                x: required(x)?,
                y: required(y)?,
                d,
            }))
        }
        "RSA" => {
            let prv = d.map(|d_val| RsaPrivateParams {
                d: d_val,
                p,
                q,
                dp,
                dq,
                qi,
            });
            Ok(JwkParams::Rsa(RsaParams {
                n: required(n)?,
                e: required(e)?,
                prv,
            }))
        }
        "oct" => Ok(JwkParams::Oct(OctParams { k: required(k)? })),
        "OKP" => {
            let crv_str = required(crv)?;
            Ok(JwkParams::Okp(OkpParams {
                crv: OkpCurve::from_str(&crv_str)?,
                x: required(x)?,
                d,
            }))
        }
        _ => Err(Report::new(JoseError::InvalidKey)),
    }
}

fn read_str_field(reader: &mut JsonReader<'_>) -> JoseResult<String> {
    reader
        .read_string()
        .change_context(JoseError::MalformedToken)
}

fn read_b64_string(reader: &mut JsonReader<'_>) -> JoseResult<Vec<u8>> {
    let s = reader
        .read_string()
        .change_context(JoseError::MalformedToken)?;
    base64url::decode(&s)
}

impl JwkSet {
    #[must_use]
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"{\"keys\":[");
        for (i, jwk) in self.keys.iter().enumerate() {
            if i > 0 {
                buf.push(b',');
            }
            buf.extend_from_slice(&jwk.to_json_bytes());
        }
        buf.extend_from_slice(b"]}");
        buf
    }

    /// # Errors
    /// Returns [`JoseError::MalformedToken`] or [`JoseError::InvalidKey`] on failure.
    pub fn from_json_bytes(bytes: &[u8]) -> JoseResult<Self> {
        let mut reader = JsonReader::new(bytes).change_context(JoseError::MalformedToken)?;
        let mut keys = None;
        while let Some(field) = reader
            .next_key()
            .change_context(JoseError::MalformedToken)?
        {
            match field {
                "keys" => {
                    keys = Some(read_jwk_array(&mut reader)?);
                }
                _ => reader
                    .skip_value()
                    .change_context(JoseError::MalformedToken)?,
            }
        }
        Ok(JwkSet {
            keys: keys
                .ok_or_else(|| Report::new(JsonError::MissingField))
                .change_context(JoseError::InvalidKey)?,
        })
    }
}

fn read_jwk_array(reader: &mut JsonReader<'_>) -> JoseResult<Vec<Jwk>> {
    let input = reader.input_bytes();
    let start = reader.current_pos();
    if input.get(start) != Some(&b'[') {
        return Err(
            Report::new(JsonError::ExpectedStringOrArray).change_context(JoseError::MalformedToken)
        );
    }

    reader
        .skip_value()
        .change_context(JoseError::MalformedToken)?;
    let end = reader.current_pos();
    let array_bytes = &input[start..end];

    let mut result = Vec::new();
    let mut pos = 1; // skip '['
    while pos < array_bytes.len() {
        if array_bytes[pos] == b']' {
            break;
        }
        if array_bytes[pos] == b',' {
            pos += 1;
            continue;
        }
        let obj_start = pos;
        let mut depth = 0u32;
        loop {
            match array_bytes.get(pos) {
                Some(b'{' | b'[') => {
                    depth += 1;
                    pos += 1;
                }
                Some(b'}' | b']') => {
                    depth -= 1;
                    pos += 1;
                    if depth == 0 {
                        break;
                    }
                }
                Some(b'"') => {
                    pos += 1;
                    while pos < array_bytes.len() {
                        match array_bytes[pos] {
                            b'"' => {
                                pos += 1;
                                break;
                            }
                            b'\\' => pos += 2,
                            _ => pos += 1,
                        }
                    }
                }
                Some(_) => pos += 1,
                None => {
                    return Err(Report::new(JsonError::UnterminatedJson)
                        .change_context(JoseError::MalformedToken));
                }
            }
        }
        result.push(Jwk::from_json_bytes(&array_bytes[obj_start..pos])?);
    }
    Ok(result)
}

// ====================================================================
// JWK Thumbprint (RFC 7638)
// ====================================================================

impl Jwk {
    /// Returns the canonical JSON bytes for thumbprint computation (RFC 7638 §3).
    ///
    /// Contains only the required members for the key type, sorted lexicographically.
    /// Hash this with SHA-256 (or another hash) to produce the thumbprint.
    #[must_use]
    pub fn thumbprint_canonical_json(&self) -> Vec<u8> {
        let mut w = JsonWriter::new();
        match &self.key {
            JwkParams::Ec(p) => {
                w.string("crv", p.crv.as_str());
                w.string("kty", self.kty());
                w.string("x", &base64url::encode(&p.x));
                w.string("y", &base64url::encode(&p.y));
            }
            JwkParams::Rsa(p) => {
                w.string("e", &base64url::encode(&p.e));
                w.string("kty", self.kty());
                w.string("n", &base64url::encode(&p.n));
            }
            JwkParams::Oct(p) => {
                w.string("k", &base64url::encode(&p.k));
                w.string("kty", self.kty());
            }
            JwkParams::Okp(p) => {
                w.string("crv", p.crv.as_str());
                w.string("kty", self.kty());
                w.string("x", &base64url::encode(&p.x));
            }
        }
        w.finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn ec_jwk_roundtrip() {
        let jwk = Jwk {
            kid: Some("test-ec".into()),
            alg: Some("ES256".into()),
            use_: Some(KeyUse::Sig),
            key_ops: None,
            key: JwkParams::Ec(EcParams {
                crv: EcCurve::P256,
                x: vec![1, 2, 3],
                y: vec![4, 5, 6],
                d: None,
            }),
        };
        let bytes = jwk.to_json_bytes();
        let parsed = Jwk::from_json_bytes(&bytes).unwrap();
        assert_eq!(parsed.kty(), "EC");
        assert_eq!(parsed.kid.as_deref(), Some("test-ec"));
        assert_eq!(parsed.alg.as_deref(), Some("ES256"));
        assert_eq!(parsed.use_, Some(KeyUse::Sig));
        match &parsed.key {
            JwkParams::Ec(p) => {
                assert_eq!(p.crv, EcCurve::P256);
                assert_eq!(p.x, vec![1, 2, 3]);
                assert_eq!(p.y, vec![4, 5, 6]);
                assert!(p.d.is_none());
            }
            _ => panic!("wrong params type"),
        }
    }

    #[test]
    fn oct_jwk_roundtrip() {
        let jwk = Jwk {
            kid: None,
            alg: None,
            use_: None,
            key_ops: None,
            key: JwkParams::Oct(OctParams { k: vec![0xAB; 32] }),
        };
        let bytes = jwk.to_json_bytes();
        let parsed = Jwk::from_json_bytes(&bytes).unwrap();
        match &parsed.key {
            JwkParams::Oct(p) => assert_eq!(p.k, vec![0xAB; 32]),
            _ => panic!("wrong params type"),
        }
    }

    #[test]
    fn jwk_set_roundtrip() {
        let set = JwkSet {
            keys: vec![
                Jwk {
                    kid: Some("key1".into()),
                    alg: None,
                    use_: None,
                    key_ops: None,
                    key: JwkParams::Oct(OctParams { k: vec![1, 2, 3] }),
                },
                Jwk {
                    kid: Some("key2".into()),
                    alg: None,
                    use_: None,
                    key_ops: None,
                    key: JwkParams::Oct(OctParams { k: vec![4, 5, 6] }),
                },
            ],
        };
        let bytes = set.to_json_bytes();
        let parsed = JwkSet::from_json_bytes(&bytes).unwrap();
        assert_eq!(parsed.keys.len(), 2);
        assert_eq!(parsed.find_by_kid("key1").unwrap().kty(), "oct");
        assert_eq!(parsed.find_by_kid("key2").unwrap().kty(), "oct");
        assert!(parsed.find_by_kid("key3").is_none());
    }

    /// RFC 7638 §3.1 test vector.
    #[test]
    fn rfc7638_thumbprint_canonical_json() {
        let jwk_json = br#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;
        let jwk = Jwk::from_json_bytes(jwk_json).unwrap();
        let canonical = jwk.thumbprint_canonical_json();
        let canonical_str = core::str::from_utf8(&canonical).unwrap();
        assert_eq!(
            canonical_str,
            r#"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}"#
        );
    }
}

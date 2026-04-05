//! JSON Web Key (RFC 7517) types and JWK Thumbprint (RFC 7638).

use alloc::string::String;
use alloc::vec::Vec;

use crate::JoseError;
use crate::base64url;
use crate::json::{JsonReader, JsonWriter};

/// Intended use of a public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyUse {
    Sig,
    Enc,
}

/// Key-type-specific parameters.
#[derive(Clone, Debug)]
pub enum JwkParams {
    Ec(EcParams),
    Rsa(RsaParams),
    Oct(OctParams),
    Okp(OkpParams),
}

/// Parameters for `kty: "EC"` keys (RFC 7518 §6.2).
#[derive(Clone, Debug)]
pub struct EcParams {
    pub crv: String,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    pub d: Option<Vec<u8>>,
}

/// Parameters for `kty: "RSA"` keys (RFC 7518 §6.3).
#[derive(Clone, Debug)]
pub struct RsaParams {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Option<Vec<u8>>,
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
    pub crv: String,
    pub x: Vec<u8>,
    pub d: Option<Vec<u8>>,
}

/// A parsed JSON Web Key (RFC 7517 §4).
#[derive(Clone, Debug)]
pub struct Jwk {
    pub kty: String,
    pub kid: Option<String>,
    pub alg: Option<String>,
    pub use_: Option<KeyUse>,
    pub key_ops: Option<Vec<String>>,
    pub params: JwkParams,
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
    /// Returns [`crate::JoseError::InvalidKey`] if the JWK does not match this key type.
    fn from_jwk(jwk: &Jwk) -> Result<Self, JoseError>;
}

/// Algorithm-level JWK conversion. Implement this on algorithm ZSTs so
/// `Key<A, K>` automatically gains `ToJwk`/`FromJwk` via blanket impls.
pub trait JwkKeyConvert<K: crate::key::KeyPurpose>: crate::key::HasKey<K> {
    fn key_to_jwk(key: &<Self as crate::key::HasKey<K>>::Key) -> Jwk;

    /// # Errors
    /// Returns [`crate::JoseError::InvalidKey`] if the JWK does not represent a valid key for this algorithm.
    fn key_from_jwk(jwk: &Jwk) -> Result<<Self as crate::key::HasKey<K>>::Key, JoseError>;
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
    fn from_jwk(jwk: &Jwk) -> Result<Self, JoseError> {
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
        w.string("kty", &self.kty);
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
            w.string_or_array("key_ops", key_ops);
        }
        match &self.params {
            JwkParams::Ec(p) => {
                w.string("crv", &p.crv);
                w.string("x", &base64url::encode(&p.x));
                w.string("y", &base64url::encode(&p.y));
                if let Some(d) = &p.d {
                    w.string("d", &base64url::encode(d));
                }
            }
            JwkParams::Rsa(p) => {
                w.string("n", &base64url::encode(&p.n));
                w.string("e", &base64url::encode(&p.e));
                if let Some(d) = &p.d {
                    w.string("d", &base64url::encode(d));
                }
                if let Some(p_val) = &p.p {
                    w.string("p", &base64url::encode(p_val));
                }
                if let Some(q) = &p.q {
                    w.string("q", &base64url::encode(q));
                }
                if let Some(dp) = &p.dp {
                    w.string("dp", &base64url::encode(dp));
                }
                if let Some(dq) = &p.dq {
                    w.string("dq", &base64url::encode(dq));
                }
                if let Some(qi) = &p.qi {
                    w.string("qi", &base64url::encode(qi));
                }
            }
            JwkParams::Oct(p) => {
                w.string("k", &base64url::encode(&p.k));
            }
            JwkParams::Okp(p) => {
                w.string("crv", &p.crv);
                w.string("x", &base64url::encode(&p.x));
                if let Some(d) = &p.d {
                    w.string("d", &base64url::encode(d));
                }
            }
        }
        w.finish()
    }

    /// # Errors
    /// Returns [`crate::JoseError::InvalidToken`] or [`crate::JoseError::Base64DecodeError`] on malformed JSON or invalid fields, or [`crate::JoseError::InvalidKey`] for unknown `kty` or bad `use`.
    #[allow(clippy::many_single_char_names)] // RFC 7518 RSA field names: n, e, d, p, q, …
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, JoseError> {
        let mut reader = JsonReader::new(bytes)?;

        let mut kty = None;
        let mut kid = None;
        let mut alg = None;
        let mut use_ = None;
        let mut key_ops = None;
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

        while let Some(key) = reader.next_key()? {
            match key {
                "kty" => kty = Some(reader.read_string()?),
                "kid" => kid = Some(reader.read_string()?),
                "alg" => alg = Some(reader.read_string()?),
                "use" => {
                    let val = reader.read_string()?;
                    use_ = Some(match val.as_str() {
                        "sig" => KeyUse::Sig,
                        "enc" => KeyUse::Enc,
                        _ => return Err(JoseError::InvalidKey),
                    });
                }
                "key_ops" => key_ops = Some(reader.read_string_array()?),
                "crv" => crv = Some(reader.read_string()?),
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
                _ => reader.skip_value()?,
            }
        }

        let kty = kty.ok_or(JoseError::InvalidKey)?;
        let params = match kty.as_str() {
            "EC" => JwkParams::Ec(EcParams {
                crv: crv.ok_or(JoseError::InvalidKey)?,
                x: x.ok_or(JoseError::InvalidKey)?,
                y: y.ok_or(JoseError::InvalidKey)?,
                d,
            }),
            "RSA" => JwkParams::Rsa(RsaParams {
                n: n.ok_or(JoseError::InvalidKey)?,
                e: e.ok_or(JoseError::InvalidKey)?,
                d,
                p,
                q,
                dp,
                dq,
                qi,
            }),
            "oct" => JwkParams::Oct(OctParams {
                k: k.ok_or(JoseError::InvalidKey)?,
            }),
            "OKP" => JwkParams::Okp(OkpParams {
                crv: crv.ok_or(JoseError::InvalidKey)?,
                x: x.ok_or(JoseError::InvalidKey)?,
                d,
            }),
            _ => return Err(JoseError::InvalidKey),
        };

        Ok(Jwk {
            kty,
            kid,
            alg,
            use_,
            key_ops,
            params,
        })
    }
}

fn read_b64_string(reader: &mut JsonReader<'_>) -> Result<Vec<u8>, JoseError> {
    let s = reader.read_string()?;
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
    /// Returns [`crate::JoseError::InvalidToken`] or [`crate::JoseError::InvalidKey`] if the JWKS JSON is malformed or missing `keys`.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, JoseError> {
        let mut reader = JsonReader::new(bytes)?;
        let mut keys = None;
        while let Some(key) = reader.next_key()? {
            match key {
                "keys" => {
                    keys = Some(read_jwk_array(&mut reader)?);
                }
                _ => reader.skip_value()?,
            }
        }
        Ok(JwkSet {
            keys: keys.ok_or(JoseError::InvalidKey)?,
        })
    }
}

fn read_jwk_array(reader: &mut JsonReader<'_>) -> Result<Vec<Jwk>, JoseError> {
    let input = reader.input_bytes();
    let start = reader.current_pos();
    if input.get(start) != Some(&b'[') {
        return Err(JoseError::InvalidToken("expected array"));
    }

    // Skip past the array in the outer reader, then parse each element
    reader.skip_value()?;
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
        // Find the extent of this object
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
                None => return Err(JoseError::InvalidToken("unterminated array")),
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
        match &self.params {
            JwkParams::Ec(p) => {
                w.string("crv", &p.crv);
                w.string("kty", &self.kty);
                w.string("x", &base64url::encode(&p.x));
                w.string("y", &base64url::encode(&p.y));
            }
            JwkParams::Rsa(p) => {
                w.string("e", &base64url::encode(&p.e));
                w.string("kty", &self.kty);
                w.string("n", &base64url::encode(&p.n));
            }
            JwkParams::Oct(p) => {
                w.string("k", &base64url::encode(&p.k));
                w.string("kty", &self.kty);
            }
            JwkParams::Okp(p) => {
                w.string("crv", &p.crv);
                w.string("kty", &self.kty);
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
            kty: "EC".into(),
            kid: Some("test-ec".into()),
            alg: Some("ES256".into()),
            use_: Some(KeyUse::Sig),
            key_ops: None,
            params: JwkParams::Ec(EcParams {
                crv: "P-256".into(),
                x: vec![1, 2, 3],
                y: vec![4, 5, 6],
                d: None,
            }),
        };
        let bytes = jwk.to_json_bytes();
        let parsed = Jwk::from_json_bytes(&bytes).unwrap();
        assert_eq!(parsed.kty, "EC");
        assert_eq!(parsed.kid.as_deref(), Some("test-ec"));
        assert_eq!(parsed.alg.as_deref(), Some("ES256"));
        assert_eq!(parsed.use_, Some(KeyUse::Sig));
        match &parsed.params {
            JwkParams::Ec(p) => {
                assert_eq!(p.crv, "P-256");
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
            kty: "oct".into(),
            kid: None,
            alg: None,
            use_: None,
            key_ops: None,
            params: JwkParams::Oct(OctParams { k: vec![0xAB; 32] }),
        };
        let bytes = jwk.to_json_bytes();
        let parsed = Jwk::from_json_bytes(&bytes).unwrap();
        match &parsed.params {
            JwkParams::Oct(p) => assert_eq!(p.k, vec![0xAB; 32]),
            _ => panic!("wrong params type"),
        }
    }

    #[test]
    fn jwk_set_roundtrip() {
        let set = JwkSet {
            keys: vec![
                Jwk {
                    kty: "oct".into(),
                    kid: Some("key1".into()),
                    alg: None,
                    use_: None,
                    key_ops: None,
                    params: JwkParams::Oct(OctParams { k: vec![1, 2, 3] }),
                },
                Jwk {
                    kty: "oct".into(),
                    kid: Some("key2".into()),
                    alg: None,
                    use_: None,
                    key_ops: None,
                    params: JwkParams::Oct(OctParams { k: vec![4, 5, 6] }),
                },
            ],
        };
        let bytes = set.to_json_bytes();
        let parsed = JwkSet::from_json_bytes(&bytes).unwrap();
        assert_eq!(parsed.keys.len(), 2);
        assert_eq!(parsed.find_by_kid("key1").unwrap().kty, "oct");
        assert_eq!(parsed.find_by_kid("key2").unwrap().kty, "oct");
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

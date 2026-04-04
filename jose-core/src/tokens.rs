use alloc::boxed::Box;
use alloc::string::String;
use core::marker::PhantomData;

use crate::algorithm::{JwsAlgorithm, Signer, Verifier};
use crate::purpose::{Purpose, Signed, SignedData};
use crate::validation::Validate;
use crate::{JoseError, SigningKey, VerifyingKey};

/// A parsed but unverified/undecrypted compact-serialized token.
///
/// For JWS this is the three-part `header.payload.signature` form.
/// The algorithm type parameter prevents using the wrong key type.
pub struct CompactToken<P: Purpose, M = Box<serde_json::value::RawValue>> {
    header_b64: String,
    data: P::SealedData,
    _marker: PhantomData<M>,
}

/// A verified/decrypted token ready to be consumed, or a new token ready to be sealed.
pub struct UnsealedToken<P: Purpose, M> {
    header_b64: String,
    pub claims: M,
    _marker: PhantomData<P>,
}

// -- Header access --

impl<P: Purpose, M> CompactToken<P, M> {
    /// Decode and return the JOSE header.
    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    /// Return the raw base64url-encoded header.
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// Validate that the header's `typ` field matches the expected value (RFC 8725 §3.11).
    pub fn require_typ(&self, expected: &str) -> Result<&Self, JoseError> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(JoseError::InvalidToken("typ mismatch")),
        }
    }
}

impl<P: Purpose, M> UnsealedToken<P, M> {
    /// Decode and return the JOSE header.
    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    /// Return the raw base64url-encoded header.
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }
}

// -- Type aliases mirroring paseto --

pub type CompactJws<A, M = Box<serde_json::value::RawValue>> = CompactToken<Signed<A>, M>;
pub type UnsignedToken<A, M> = UnsealedToken<Signed<A>, M>;

// -- UnsealedToken constructors --

impl<A: JwsAlgorithm, M> UnsealedToken<Signed<A>, M> {
    /// Create a new unsigned token with the given claims and a minimal `{"alg":"..."}` header.
    pub fn new(claims: M) -> Self {
        let header_b64 = crate::header::HeaderBuilder::new(A::ALG).build();
        UnsealedToken {
            header_b64,
            claims,
            _marker: PhantomData,
        }
    }

    /// Create a new unsigned token with a pre-built base64url-encoded header.
    pub fn with_header(header_b64: String, claims: M) -> Self {
        UnsealedToken {
            header_b64,
            claims,
            _marker: PhantomData,
        }
    }
}

// -- Signing --

impl<A, M> UnsealedToken<Signed<A>, M>
where
    A: Signer,
    M: serde::Serialize,
{
    pub fn sign(self, key: &SigningKey<A>) -> Result<CompactJws<A, M>, JoseError> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let header: AlgHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?;
        if header.alg != A::ALG {
            return Err(JoseError::InvalidToken("header alg does not match type parameter"));
        }

        let payload_bytes = serde_json::to_vec(&self.claims)
            .map_err(|e| JoseError::PayloadError(alloc::boxed::Box::new(e)))?;
        let payload_b64 = crate::base64url::encode(&payload_bytes);

        let signing_input = alloc::format!("{}.{}", self.header_b64, payload_b64);
        let signature = A::sign(key.inner(), signing_input.as_bytes())?;

        Ok(CompactToken {
            header_b64: self.header_b64,
            data: SignedData {
                payload_b64,
                signature,
            },
            _marker: PhantomData,
        })
    }
}

// -- Verification --

impl<A, M> CompactToken<Signed<A>, M>
where
    A: Verifier,
    M: serde::de::DeserializeOwned,
{
    pub fn verify(
        self,
        key: &VerifyingKey<A>,
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsealedToken<Signed<A>, M>, JoseError> {
        let signing_input = alloc::format!("{}.{}", self.header_b64, self.data.payload_b64);
        A::verify(key.inner(), signing_input.as_bytes(), &self.data.signature)?;

        let payload_bytes = crate::base64url::decode(&self.data.payload_b64)?;
        let claims: M = serde_json::from_slice(&payload_bytes)
            .map_err(|e| JoseError::PayloadError(alloc::boxed::Box::new(e)))?;

        v.validate(&claims)?;

        Ok(UnsealedToken {
            header_b64: self.header_b64,
            claims,
            _marker: PhantomData,
        })
    }
}

// -- Display (compact serialization) --

impl<A: JwsAlgorithm, M> core::fmt::Display for CompactToken<Signed<A>, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            self.header_b64,
            self.data.payload_b64,
            crate::base64url::encode(&self.data.signature),
        )
    }
}

// -- FromStr (compact deserialization) --

impl<A: JwsAlgorithm, M> core::str::FromStr for CompactToken<Signed<A>, M> {
    type Err = JoseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '.');
        let header_b64 = parts.next().ok_or(JoseError::InvalidToken("missing header"))?;
        let payload_b64 = parts.next().ok_or(JoseError::InvalidToken("missing payload"))?;
        let signature_b64 = parts
            .next()
            .ok_or(JoseError::InvalidToken("missing signature"))?;

        let header_bytes = crate::base64url::decode(header_b64)?;
        let header: AlgHeader = serde_json::from_slice(&header_bytes)
            .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?;
        if header.alg != A::ALG {
            return Err(JoseError::InvalidToken("alg mismatch"));
        }
        // RFC 7515 §4.1.11: reject tokens with unrecognized critical extensions
        if header.crit.is_some() {
            return Err(JoseError::InvalidToken("unsupported crit extension"));
        }

        let signature = crate::base64url::decode(signature_b64)?;

        Ok(CompactToken {
            header_b64: String::from(header_b64),
            data: SignedData {
                payload_b64: String::from(payload_b64),
                signature,
            },
            _marker: PhantomData,
        })
    }
}

#[derive(serde::Deserialize)]
struct AlgHeader<'a> {
    alg: &'a str,
    #[serde(default)]
    crit: Option<alloc::vec::Vec<&'a str>>,
}

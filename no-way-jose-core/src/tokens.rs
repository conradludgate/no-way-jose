use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::algorithm::{JwsAlgorithm, Signer, Verifier};
use crate::json::{FromJson, JsonReader, RawJson, ToJson};
use crate::jwe_algorithm::{
    ContentDecryptor, ContentEncryptor, JweContentEncryption, JweKeyManagement, KeyDecryptor,
    KeyEncryptor,
};
use crate::purpose::{Encrypted, EncryptedData, Purpose, Signed, SignedData};
use crate::validation::Validate;
use crate::{DecryptionKey, EncryptionKey, JoseError, SigningKey, VerifyingKey};

/// A parsed but unverified/undecrypted compact-serialized token.
///
/// For JWS this is the three-part `header.payload.signature` form.
/// The algorithm type parameter prevents using the wrong key type.
pub struct CompactToken<P: Purpose, M = RawJson> {
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
    ///
    /// # Errors
    /// Returns [`JoseError::Base64DecodeError`] or [`JoseError::InvalidToken`] if the header cannot be parsed.
    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    /// Return the raw base64url-encoded header.
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// Validate that the header's `typ` field matches the expected value (RFC 8725 §3.11).
    ///
    /// # Errors
    /// Returns [`JoseError::InvalidToken`] if `typ` is missing or does not match `expected`.
    pub fn require_typ(self, expected: &str) -> Result<Self, JoseError> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(JoseError::InvalidToken("typ mismatch")),
        }
    }
}

impl<P: Purpose, M> UnsealedToken<P, M> {
    /// Decode and return the JOSE header.
    ///
    /// # Errors
    /// Returns [`JoseError::Base64DecodeError`] or [`JoseError::InvalidToken`] if the header cannot be parsed.
    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    /// Return the raw base64url-encoded header.
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }
}

// -- Type aliases --

pub type CompactJws<A, M = RawJson> = CompactToken<Signed<A>, M>;
pub type UnsignedToken<A, M> = UnsealedToken<Signed<A>, M>;
pub type CompactJwe<KM, CE, M = RawJson> = CompactToken<Encrypted<KM, CE>, M>;

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

    /// Start building an unsigned token with optional header fields.
    #[must_use]
    pub fn builder(claims: M) -> TokenBuilder<Signed<A>, M> {
        TokenBuilder {
            header: crate::header::HeaderBuilder::new(A::ALG),
            claims,
            _marker: PhantomData,
        }
    }
}

// -- Signing --

impl<A, M> UnsealedToken<Signed<A>, M>
where
    A: Signer,
    M: ToJson,
{
    /// # Errors
    /// Returns [`JoseError::InvalidToken`], [`JoseError::Base64DecodeError`], [`JoseError::CryptoError`], or related errors if signing fails.
    pub fn sign(self, key: &SigningKey<A>) -> Result<CompactJws<A, M>, JoseError> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let hdr = parse_header(&header_bytes)?;
        if hdr.alg != A::ALG {
            return Err(JoseError::InvalidToken(
                "header alg does not match type parameter",
            ));
        }

        let payload_bytes = self.claims.to_json_bytes();
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
    M: FromJson,
{
    /// # Errors
    /// Returns [`JoseError::CryptoError`], [`JoseError::Base64DecodeError`], [`JoseError::PayloadError`], [`JoseError::ClaimsError`], or [`JoseError::InvalidToken`] on failure.
    pub fn verify(
        self,
        key: &VerifyingKey<A>,
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsealedToken<Signed<A>, M>, JoseError> {
        let signing_input = alloc::format!("{}.{}", self.header_b64, self.data.payload_b64);
        A::verify(key.inner(), signing_input.as_bytes(), &self.data.signature)?;

        let payload_bytes = crate::base64url::decode(&self.data.payload_b64)?;
        let claims: M = M::from_json_bytes(&payload_bytes).map_err(JoseError::PayloadError)?;

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

struct JwsParts {
    alg: String,
    header_b64: String,
    payload_b64: String,
    signature: Vec<u8>,
}

fn parse_jws_compact(s: &str) -> Result<JwsParts, JoseError> {
    let mut parts = s.splitn(3, '.');
    let header_b64 = parts
        .next()
        .ok_or(JoseError::InvalidToken("missing header"))?;
    let payload_b64 = parts
        .next()
        .ok_or(JoseError::InvalidToken("missing payload"))?;
    let signature_b64 = parts
        .next()
        .ok_or(JoseError::InvalidToken("missing signature"))?;

    let header_bytes = crate::base64url::decode(header_b64)?;
    let hdr = parse_header(&header_bytes)?;
    if hdr.crit.is_some() {
        return Err(JoseError::InvalidToken("unsupported crit extension"));
    }

    let signature = crate::base64url::decode(signature_b64)?;

    Ok(JwsParts {
        alg: hdr.alg,
        header_b64: String::from(header_b64),
        payload_b64: String::from(payload_b64),
        signature,
    })
}

impl<A: JwsAlgorithm, M> core::str::FromStr for CompactToken<Signed<A>, M> {
    type Err = JoseError;

    /// # Errors
    /// Returns [`JoseError::InvalidToken`] or [`JoseError::Base64DecodeError`] if the string is not a valid compact JWS or `alg` mismatches.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = parse_jws_compact(s)?;
        if parts.alg != A::ALG {
            return Err(JoseError::InvalidToken("alg mismatch"));
        }
        Ok(CompactToken {
            header_b64: parts.header_b64,
            data: SignedData {
                payload_b64: parts.payload_b64,
                signature: parts.signature,
            },
            _marker: PhantomData,
        })
    }
}

// -- Untyped JWS (dynamic algorithm dispatch) --

/// A parsed JWS compact token without a statically known algorithm.
///
/// Use this when the algorithm must be determined at runtime (e.g., JWKS flows).
/// Call `into_typed::<A>()` to convert to a typed `CompactJws<A, M>` after
/// inspecting the `alg` header.
pub struct UntypedCompactJws<M = RawJson> {
    alg: String,
    header_b64: String,
    data: SignedData,
    _marker: PhantomData<M>,
}

impl<M> UntypedCompactJws<M> {
    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// # Errors
    /// Returns [`JoseError::Base64DecodeError`] or [`JoseError::InvalidToken`] if the header cannot be parsed.
    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    #[must_use]
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// # Errors
    /// Returns [`JoseError::InvalidToken`] if `typ` is missing or does not match `expected`.
    pub fn require_typ(self, expected: &str) -> Result<Self, JoseError> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(JoseError::InvalidToken("typ mismatch")),
        }
    }

    /// # Errors
    /// Returns [`JoseError::InvalidToken`] if the runtime `alg` does not match `A::ALG`.
    pub fn into_typed<A: JwsAlgorithm>(self) -> Result<CompactJws<A, M>, JoseError> {
        if self.alg != A::ALG {
            return Err(JoseError::InvalidToken("alg mismatch"));
        }
        Ok(CompactToken {
            header_b64: self.header_b64,
            data: self.data,
            _marker: PhantomData,
        })
    }
}

impl<M> core::str::FromStr for UntypedCompactJws<M> {
    type Err = JoseError;

    /// # Errors
    /// Returns [`JoseError::InvalidToken`] or [`JoseError::Base64DecodeError`] if the string is not a valid compact JWS.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = parse_jws_compact(s)?;
        Ok(UntypedCompactJws {
            alg: parts.alg,
            header_b64: parts.header_b64,
            data: SignedData {
                payload_b64: parts.payload_b64,
                signature: parts.signature,
            },
            _marker: PhantomData,
        })
    }
}

impl<M> core::fmt::Display for UntypedCompactJws<M> {
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

// ====================================================================
// JWE — Encrypted tokens
// ====================================================================

impl<KM: JweKeyManagement, CE: JweContentEncryption, M> UnsealedToken<Encrypted<KM, CE>, M> {
    pub fn new(claims: M) -> Self {
        let header_b64 = crate::header::HeaderBuilder::new(KM::ALG)
            .enc(CE::ENC)
            .build();
        UnsealedToken {
            header_b64,
            claims,
            _marker: PhantomData,
        }
    }

    pub fn with_header(header_b64: String, claims: M) -> Self {
        UnsealedToken {
            header_b64,
            claims,
            _marker: PhantomData,
        }
    }

    /// Start building an encrypted token with optional header fields.
    #[must_use]
    pub fn builder(claims: M) -> TokenBuilder<Encrypted<KM, CE>, M> {
        TokenBuilder {
            header: crate::header::HeaderBuilder::new(KM::ALG).enc(CE::ENC),
            claims,
            _marker: PhantomData,
        }
    }
}

// -- Encryption --

impl<KM, CE, M> UnsealedToken<Encrypted<KM, CE>, M>
where
    KM: KeyEncryptor,
    CE: ContentEncryptor,
    M: ToJson,
{
    /// # Errors
    /// Returns [`JoseError::InvalidToken`], [`JoseError::Base64DecodeError`], [`JoseError::CryptoError`], or related errors if encryption fails.
    pub fn encrypt(self, key: &EncryptionKey<KM>) -> Result<CompactJwe<KM, CE, M>, JoseError> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let hdr = parse_header(&header_bytes)?;
        if hdr.alg != KM::ALG {
            return Err(JoseError::InvalidToken(
                "header alg does not match key management type",
            ));
        }
        match hdr.enc.as_deref() {
            Some(e) if e == CE::ENC => {}
            _ => {
                return Err(JoseError::InvalidToken(
                    "header enc does not match content encryption type",
                ));
            }
        }

        let result = KM::encrypt_cek(key.inner(), CE::KEY_LEN)?;

        let header_b64 = if result.extra_headers.is_empty() {
            self.header_b64
        } else {
            rebuild_header_with_extras(&header_bytes, &result.extra_headers)
        };

        let plaintext = self.claims.to_json_bytes();
        let aad = header_b64.as_bytes();
        let output = CE::encrypt(&result.cek, aad, &plaintext)?;

        Ok(CompactToken {
            header_b64,
            data: EncryptedData {
                encrypted_key: result.encrypted_key,
                iv: output.iv,
                ciphertext: output.ciphertext,
                tag: output.tag,
            },
            _marker: PhantomData,
        })
    }
}

// -- Decryption --

impl<KM, CE, M> CompactToken<Encrypted<KM, CE>, M>
where
    KM: KeyDecryptor,
    CE: ContentDecryptor,
    M: FromJson,
{
    /// # Errors
    /// Returns [`JoseError::CryptoError`], [`JoseError::PayloadError`], [`JoseError::ClaimsError`], or [`JoseError::InvalidToken`] on failure.
    pub fn decrypt(
        self,
        key: &DecryptionKey<KM>,
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsealedToken<Encrypted<KM, CE>, M>, JoseError> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let cek = KM::decrypt_cek(
            key.inner(),
            &self.data.encrypted_key,
            &header_bytes,
            CE::KEY_LEN,
        )?;

        let aad = self.header_b64.as_bytes();
        let plaintext = CE::decrypt(
            &cek,
            &self.data.iv,
            aad,
            &self.data.ciphertext,
            &self.data.tag,
        )?;

        let claims: M = M::from_json_bytes(&plaintext).map_err(JoseError::PayloadError)?;
        v.validate(&claims)?;

        Ok(UnsealedToken {
            header_b64: self.header_b64,
            claims,
            _marker: PhantomData,
        })
    }
}

// -- Display (JWE 5-part compact serialization) --

impl<KM: JweKeyManagement, CE: JweContentEncryption, M> core::fmt::Display
    for CompactToken<Encrypted<KM, CE>, M>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}.{}",
            self.header_b64,
            crate::base64url::encode(&self.data.encrypted_key),
            crate::base64url::encode(&self.data.iv),
            crate::base64url::encode(&self.data.ciphertext),
            crate::base64url::encode(&self.data.tag),
        )
    }
}

// -- FromStr (JWE 5-part compact deserialization) --

impl<KM: JweKeyManagement, CE: JweContentEncryption, M> core::str::FromStr
    for CompactToken<Encrypted<KM, CE>, M>
{
    type Err = JoseError;

    /// # Errors
    /// Returns [`JoseError::InvalidToken`] or [`JoseError::Base64DecodeError`] if the string is not a valid compact JWE or algorithms mismatch.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(5, '.');
        let header_b64 = parts
            .next()
            .ok_or(JoseError::InvalidToken("missing header"))?;
        let ek_b64 = parts
            .next()
            .ok_or(JoseError::InvalidToken("missing encrypted_key"))?;
        let iv_b64 = parts.next().ok_or(JoseError::InvalidToken("missing iv"))?;
        let ct_b64 = parts
            .next()
            .ok_or(JoseError::InvalidToken("missing ciphertext"))?;
        let tag_b64 = parts.next().ok_or(JoseError::InvalidToken("missing tag"))?;

        let header_bytes = crate::base64url::decode(header_b64)?;
        let hdr = parse_header(&header_bytes)?;
        if hdr.alg != KM::ALG {
            return Err(JoseError::InvalidToken("alg mismatch"));
        }
        let enc = hdr
            .enc
            .ok_or(JoseError::InvalidToken("missing enc in header"))?;
        if enc != CE::ENC {
            return Err(JoseError::InvalidToken("enc mismatch"));
        }
        if hdr.crit.is_some() {
            return Err(JoseError::InvalidToken("unsupported crit extension"));
        }

        let encrypted_key = crate::base64url::decode(ek_b64)?;
        let iv = crate::base64url::decode(iv_b64)?;
        let ciphertext = crate::base64url::decode(ct_b64)?;
        let tag = crate::base64url::decode(tag_b64)?;

        Ok(CompactToken {
            header_b64: String::from(header_b64),
            data: EncryptedData {
                encrypted_key,
                iv,
                ciphertext,
                tag,
            },
            _marker: PhantomData,
        })
    }
}

// ====================================================================
// Token builder
// ====================================================================

/// Fluent builder for constructing tokens with optional header fields.
///
/// Obtained via [`UnsealedToken::builder`]. Call [`build`](Self::build) to
/// produce the final [`UnsealedToken`].
pub struct TokenBuilder<P: Purpose, M> {
    header: crate::header::HeaderBuilder,
    claims: M,
    _marker: PhantomData<P>,
}

impl<P: Purpose, M> TokenBuilder<P, M> {
    /// Set the `kid` (Key ID) header parameter.
    #[must_use]
    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.header = self.header.kid(kid);
        self
    }

    /// Set the `typ` (Type) header parameter (e.g. `"JWT"`).
    #[must_use]
    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.header = self.header.typ(typ);
        self
    }

    /// Finalize and return the [`UnsealedToken`].
    #[must_use]
    pub fn build(self) -> UnsealedToken<P, M> {
        UnsealedToken {
            header_b64: self.header.build(),
            claims: self.claims,
            _marker: PhantomData,
        }
    }
}

/// Splice extra key-value pairs into an existing compact JSON header and re-encode as base64url.
fn rebuild_header_with_extras(header_bytes: &[u8], extras: &[(String, Vec<u8>)]) -> String {
    let closing = header_bytes
        .iter()
        .rposition(|&b| b == b'}')
        .expect("header must contain '}'");
    let mut buf = Vec::with_capacity(header_bytes.len() + extras.len() * 32);
    buf.extend_from_slice(&header_bytes[..closing]);
    for (key, value) in extras {
        buf.push(b',');
        crate::json::write_json_key(&mut buf, key);
        buf.extend_from_slice(value);
    }
    buf.push(b'}');
    crate::base64url::encode(&buf)
}

struct ParsedHeader {
    alg: String,
    enc: Option<String>,
    crit: Option<Vec<String>>,
}

/// Single-pass extraction of `alg`, optional `enc`, and optional `crit` from a JOSE header.
fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, JoseError> {
    let mut reader =
        JsonReader::new(bytes).map_err(|_| JoseError::InvalidToken("malformed header JSON"))?;
    let mut alg = None;
    let mut enc = None;
    let mut crit = None;
    while let Some(key) = reader
        .next_key()
        .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?
    {
        match key {
            "alg" => {
                alg = Some(
                    reader
                        .read_string()
                        .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
                );
            }
            "enc" => {
                enc = Some(
                    reader
                        .read_string()
                        .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
                );
            }
            "crit" => {
                crit = Some(
                    reader
                        .read_string_array()
                        .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
                );
            }
            _ => reader
                .skip_value()
                .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
        }
    }
    Ok(ParsedHeader {
        alg: alg.ok_or(JoseError::InvalidToken("missing alg in header"))?,
        enc,
        crit,
    })
}

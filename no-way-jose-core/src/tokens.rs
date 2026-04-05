use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use error_stack::{Report, ResultExt};

use crate::algorithm::{JwsAlgorithm, Signer, Verifier};
use crate::error::{HeaderError, JoseError, JoseResult, TokenFormatError};
use crate::json::{FromJson, JsonReader, RawJson, ToJson};
use crate::jwe_algorithm::{
    ContentDecryptor, ContentEncryptor, JweContentEncryption, JweKeyManagement, KeyDecryptor,
    KeyEncryptor,
};
use crate::purpose::{Encrypted, EncryptedData, Purpose, Signed, SignedData};
use crate::validation::Validate;
use crate::{DecryptionKey, EncryptionKey, SigningKey, VerifyingKey};

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
    /// Returns [`JoseError::Base64Decode`] or [`JoseError::MalformedToken`] if the header cannot be parsed.
    pub fn header(&self) -> JoseResult<crate::header::OwnedHeader> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    /// Return the raw base64url-encoded header.
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// Validate that the header's `typ` field matches the expected value (RFC 8725 §3.11).
    ///
    /// # Errors
    /// Returns [`JoseError::HeaderValidation`] if `typ` is missing or does not match `expected`.
    pub fn require_typ(self, expected: &str) -> JoseResult<Self> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(Report::new(JoseError::HeaderValidation(
                HeaderError::TypMismatch,
            ))),
        }
    }

    /// Validate that the header's `cty` field matches the expected value (RFC 7519 §5.2).
    ///
    /// # Errors
    /// Returns [`JoseError::HeaderValidation`] if `cty` is missing or does not match `expected`.
    pub fn require_cty(self, expected: &str) -> JoseResult<Self> {
        let header = self.header()?;
        match header.cty.as_deref() {
            Some(c) if c.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(Report::new(JoseError::HeaderValidation(
                HeaderError::CtyMismatch,
            ))),
        }
    }
}

impl<P: Purpose, M> UnsealedToken<P, M> {
    /// Decode and return the JOSE header.
    ///
    /// # Errors
    /// Returns [`JoseError::Base64Decode`] or [`JoseError::MalformedToken`] if the header cannot be parsed.
    pub fn header(&self) -> JoseResult<crate::header::OwnedHeader> {
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
    /// Returns a [`JoseError`] if signing fails.
    pub fn sign(self, key: &SigningKey<A>) -> JoseResult<CompactJws<A, M>> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let hdr = parse_header(&header_bytes)?;
        if hdr.alg != A::ALG {
            return Err(Report::new(JoseError::AlgorithmMismatch));
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
    /// Returns a [`JoseError`] if verification or claims validation fails.
    pub fn verify(
        self,
        key: &VerifyingKey<A>,
        v: &impl Validate<Claims = M>,
    ) -> JoseResult<UnsealedToken<Signed<A>, M>> {
        let signing_input = alloc::format!("{}.{}", self.header_b64, self.data.payload_b64);
        A::verify(key.inner(), signing_input.as_bytes(), &self.data.signature)?;

        let payload_bytes = crate::base64url::decode(&self.data.payload_b64)?;
        let claims: M = M::from_json_bytes(&payload_bytes)
            .map_err(|e| Report::new(JoseError::PayloadError).attach(e))?;

        v.validate(&claims).map_err(Report::new)?;

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

fn parse_jws_compact(s: &str) -> JoseResult<JwsParts> {
    let mut parts = s.splitn(3, '.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingHeader))
        .change_context(JoseError::MalformedToken)?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingPayload))
        .change_context(JoseError::MalformedToken)?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingSignature))
        .change_context(JoseError::MalformedToken)?;

    let header_bytes = crate::base64url::decode(header_b64)?;
    let hdr = parse_header(&header_bytes)?;
    if hdr.crit.is_some() {
        return Err(Report::new(JoseError::HeaderValidation(
            HeaderError::UnsupportedCritExtension,
        )));
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
    type Err = Report<JoseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = parse_jws_compact(s)?;
        if parts.alg != A::ALG {
            return Err(Report::new(JoseError::AlgorithmMismatch));
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
    /// Returns [`JoseError::Base64Decode`] or [`JoseError::MalformedToken`] if the header cannot be parsed.
    pub fn header(&self) -> JoseResult<crate::header::OwnedHeader> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    #[must_use]
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// # Errors
    /// Returns [`JoseError::HeaderValidation`] if `typ` is missing or does not match `expected`.
    pub fn require_typ(self, expected: &str) -> JoseResult<Self> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(Report::new(JoseError::HeaderValidation(
                HeaderError::TypMismatch,
            ))),
        }
    }

    /// # Errors
    /// Returns [`JoseError::HeaderValidation`] if `cty` is missing or does not match `expected`.
    pub fn require_cty(self, expected: &str) -> JoseResult<Self> {
        let header = self.header()?;
        match header.cty.as_deref() {
            Some(c) if c.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(Report::new(JoseError::HeaderValidation(
                HeaderError::CtyMismatch,
            ))),
        }
    }

    /// # Errors
    /// Returns [`JoseError::AlgorithmMismatch`] if the runtime `alg` does not match `A::ALG`.
    pub fn into_typed<A: JwsAlgorithm>(self) -> JoseResult<CompactJws<A, M>> {
        if self.alg != A::ALG {
            return Err(Report::new(JoseError::AlgorithmMismatch));
        }
        Ok(CompactToken {
            header_b64: self.header_b64,
            data: self.data,
            _marker: PhantomData,
        })
    }
}

impl<M> core::str::FromStr for UntypedCompactJws<M> {
    type Err = Report<JoseError>;

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
    /// Returns a [`JoseError`] if encryption fails.
    pub fn encrypt(self, key: &EncryptionKey<KM>) -> JoseResult<CompactJwe<KM, CE, M>> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let hdr = parse_header(&header_bytes)?;
        if hdr.alg != KM::ALG {
            return Err(Report::new(JoseError::AlgorithmMismatch));
        }
        match hdr.enc.as_deref() {
            Some(e) if e == CE::ENC => {}
            _ => {
                return Err(Report::new(JoseError::AlgorithmMismatch));
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
    /// Returns a [`JoseError`] if decryption or claims validation fails.
    pub fn decrypt(
        self,
        key: &DecryptionKey<KM>,
        v: &impl Validate<Claims = M>,
    ) -> JoseResult<UnsealedToken<Encrypted<KM, CE>, M>> {
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

        let claims: M = M::from_json_bytes(&plaintext)
            .map_err(|e| Report::new(JoseError::PayloadError).attach(e))?;
        v.validate(&claims).map_err(Report::new)?;

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

struct JweParts {
    alg: String,
    enc: String,
    header_b64: String,
    encrypted_key: Vec<u8>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

fn parse_jwe_compact(s: &str) -> JoseResult<JweParts> {
    let mut parts = s.splitn(5, '.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingHeader))
        .change_context(JoseError::MalformedToken)?;
    let ek_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingEncryptedKey))
        .change_context(JoseError::MalformedToken)?;
    let iv_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingIv))
        .change_context(JoseError::MalformedToken)?;
    let ct_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingCiphertext))
        .change_context(JoseError::MalformedToken)?;
    let tag_b64 = parts
        .next()
        .ok_or_else(|| Report::new(TokenFormatError::MissingTag))
        .change_context(JoseError::MalformedToken)?;

    let header_bytes = crate::base64url::decode(header_b64)?;
    let hdr = parse_header(&header_bytes)?;
    if hdr.crit.is_some() {
        return Err(Report::new(JoseError::HeaderValidation(
            HeaderError::UnsupportedCritExtension,
        )));
    }
    let enc = hdr
        .enc
        .ok_or_else(|| Report::new(TokenFormatError::MissingEnc))
        .change_context(JoseError::MalformedToken)?;

    Ok(JweParts {
        alg: hdr.alg,
        enc,
        header_b64: String::from(header_b64),
        encrypted_key: crate::base64url::decode(ek_b64)?,
        iv: crate::base64url::decode(iv_b64)?,
        ciphertext: crate::base64url::decode(ct_b64)?,
        tag: crate::base64url::decode(tag_b64)?,
    })
}

impl<KM: JweKeyManagement, CE: JweContentEncryption, M> core::str::FromStr
    for CompactToken<Encrypted<KM, CE>, M>
{
    type Err = Report<JoseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = parse_jwe_compact(s)?;
        if parts.alg != KM::ALG {
            return Err(Report::new(JoseError::AlgorithmMismatch));
        }
        if parts.enc != CE::ENC {
            return Err(Report::new(JoseError::AlgorithmMismatch));
        }
        Ok(CompactToken {
            header_b64: parts.header_b64,
            data: EncryptedData {
                encrypted_key: parts.encrypted_key,
                iv: parts.iv,
                ciphertext: parts.ciphertext,
                tag: parts.tag,
            },
            _marker: PhantomData,
        })
    }
}

// -- Untyped JWE (dynamic algorithm dispatch) --

/// A parsed JWE compact token without statically known algorithms.
///
/// Use this when the key management and content encryption algorithms must be
/// determined at runtime. Call [`into_typed::<KM, CE>()`](Self::into_typed)
/// after inspecting [`alg()`](Self::alg) and [`enc()`](Self::enc).
pub struct UntypedCompactJwe<M = RawJson> {
    alg: String,
    enc: String,
    header_b64: String,
    data: EncryptedData,
    _marker: PhantomData<M>,
}

impl<M> UntypedCompactJwe<M> {
    /// The key management algorithm (`alg` header).
    #[must_use]
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// The content encryption algorithm (`enc` header).
    #[must_use]
    pub fn enc(&self) -> &str {
        &self.enc
    }

    /// # Errors
    /// Returns [`JoseError::Base64Decode`] or [`JoseError::MalformedToken`] if the header cannot be parsed.
    pub fn header(&self) -> JoseResult<crate::header::OwnedHeader> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    #[must_use]
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// # Errors
    /// Returns [`JoseError::HeaderValidation`] if `typ` is missing or does not match `expected`.
    pub fn require_typ(self, expected: &str) -> JoseResult<Self> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(Report::new(JoseError::HeaderValidation(
                HeaderError::TypMismatch,
            ))),
        }
    }

    /// # Errors
    /// Returns [`JoseError::HeaderValidation`] if `cty` is missing or does not match `expected`.
    pub fn require_cty(self, expected: &str) -> JoseResult<Self> {
        let header = self.header()?;
        match header.cty.as_deref() {
            Some(c) if c.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(Report::new(JoseError::HeaderValidation(
                HeaderError::CtyMismatch,
            ))),
        }
    }

    /// Convert to a typed `CompactJwe<KM, CE, M>` after verifying algorithm match.
    ///
    /// # Errors
    /// Returns [`JoseError::AlgorithmMismatch`] if the runtime `alg` or `enc` does not match.
    pub fn into_typed<KM: JweKeyManagement, CE: JweContentEncryption>(
        self,
    ) -> JoseResult<CompactJwe<KM, CE, M>> {
        if self.alg != KM::ALG {
            return Err(Report::new(JoseError::AlgorithmMismatch));
        }
        if self.enc != CE::ENC {
            return Err(Report::new(JoseError::AlgorithmMismatch));
        }
        Ok(CompactToken {
            header_b64: self.header_b64,
            data: self.data,
            _marker: PhantomData,
        })
    }
}

impl<M> core::str::FromStr for UntypedCompactJwe<M> {
    type Err = Report<JoseError>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts = parse_jwe_compact(s)?;
        Ok(UntypedCompactJwe {
            alg: parts.alg,
            enc: parts.enc,
            header_b64: parts.header_b64,
            data: EncryptedData {
                encrypted_key: parts.encrypted_key,
                iv: parts.iv,
                ciphertext: parts.ciphertext,
                tag: parts.tag,
            },
            _marker: PhantomData,
        })
    }
}

impl<M> core::fmt::Display for UntypedCompactJwe<M> {
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

    /// Set the `cty` (Content Type) header parameter (e.g. `"JWT"` for nested tokens).
    #[must_use]
    pub fn cty(mut self, cty: impl Into<String>) -> Self {
        self.header = self.header.cty(cty);
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

fn parse_header(bytes: &[u8]) -> JoseResult<ParsedHeader> {
    let mut reader = JsonReader::new(bytes).change_context(JoseError::MalformedToken)?;
    let mut alg = None;
    let mut enc = None;
    let mut crit = None;
    while let Some(key) = reader
        .next_key()
        .change_context(JoseError::MalformedToken)?
    {
        match key {
            "alg" => {
                alg = Some(
                    reader
                        .read_string()
                        .change_context(JoseError::MalformedToken)?,
                );
            }
            "enc" => {
                enc = Some(
                    reader
                        .read_string()
                        .change_context(JoseError::MalformedToken)?,
                );
            }
            "crit" => {
                crit = Some(
                    reader
                        .read_string_array()
                        .change_context(JoseError::MalformedToken)?,
                );
            }
            _ => reader
                .skip_value()
                .change_context(JoseError::MalformedToken)?,
        }
    }
    Ok(ParsedHeader {
        alg: alg
            .ok_or_else(|| Report::new(TokenFormatError::MissingAlg))
            .change_context(JoseError::MalformedToken)?,
        enc,
        crit,
    })
}

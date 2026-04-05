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
    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    /// Return the raw base64url-encoded header.
    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    /// Validate that the header's `typ` field matches the expected value (RFC 8725 §3.11).
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
}

// -- Signing --

impl<A, M> UnsealedToken<Signed<A>, M>
where
    A: Signer,
    M: ToJson,
{
    pub fn sign(self, key: &SigningKey<A>) -> Result<CompactJws<A, M>, JoseError> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let (alg, _) = parse_alg_header(&header_bytes)?;
        if alg != A::ALG {
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

impl<A: JwsAlgorithm, M> core::str::FromStr for CompactToken<Signed<A>, M> {
    type Err = JoseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
        let (alg, crit) = parse_alg_header(&header_bytes)?;
        if alg != A::ALG {
            return Err(JoseError::InvalidToken("alg mismatch"));
        }
        // RFC 7515 §4.1.11: reject tokens with unrecognized critical extensions
        if crit.is_some() {
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
    pub fn alg(&self) -> &str {
        &self.alg
    }

    pub fn header(&self) -> Result<crate::header::OwnedHeader, JoseError> {
        crate::header::parse_header_owned(&self.header_b64)
    }

    pub fn raw_header_b64(&self) -> &str {
        &self.header_b64
    }

    pub fn require_typ(self, expected: &str) -> Result<Self, JoseError> {
        let header = self.header()?;
        match header.typ.as_deref() {
            Some(t) if t.eq_ignore_ascii_case(expected) => Ok(self),
            _ => Err(JoseError::InvalidToken("typ mismatch")),
        }
    }

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

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
        let (alg, crit) = parse_alg_header(&header_bytes)?;
        if crit.is_some() {
            return Err(JoseError::InvalidToken("unsupported crit extension"));
        }

        let signature = crate::base64url::decode(signature_b64)?;

        Ok(UntypedCompactJws {
            alg,
            header_b64: String::from(header_b64),
            data: SignedData {
                payload_b64: String::from(payload_b64),
                signature,
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
}

// -- Encryption --

impl<KM, CE, M> UnsealedToken<Encrypted<KM, CE>, M>
where
    KM: KeyEncryptor,
    CE: ContentEncryptor,
    M: ToJson,
{
    pub fn encrypt(self, key: &EncryptionKey<KM>) -> Result<CompactJwe<KM, CE, M>, JoseError> {
        let header_bytes = crate::base64url::decode(&self.header_b64)?;
        let (alg, enc) = parse_alg_enc_header(&header_bytes)?;
        if alg != KM::ALG {
            return Err(JoseError::InvalidToken(
                "header alg does not match key management type",
            ));
        }
        if enc != CE::ENC {
            return Err(JoseError::InvalidToken(
                "header enc does not match content encryption type",
            ));
        }

        let (encrypted_key, cek) = KM::encrypt_cek(key.inner(), CE::KEY_LEN)?;

        let plaintext = self.claims.to_json_bytes();
        let aad = self.header_b64.as_bytes();
        let output = CE::encrypt(&cek, aad, &plaintext)?;

        Ok(CompactToken {
            header_b64: self.header_b64,
            data: EncryptedData {
                encrypted_key,
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
    pub fn decrypt(
        self,
        key: &DecryptionKey<KM>,
        v: &impl Validate<Claims = M>,
    ) -> Result<UnsealedToken<Encrypted<KM, CE>, M>, JoseError> {
        let cek = KM::decrypt_cek(key.inner(), &self.data.encrypted_key)?;

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
        let (alg, enc) = parse_alg_enc_header(&header_bytes)?;
        if alg != KM::ALG {
            return Err(JoseError::InvalidToken("alg mismatch"));
        }
        if enc != CE::ENC {
            return Err(JoseError::InvalidToken("enc mismatch"));
        }

        // Reject crit for now
        let (_, crit) = parse_alg_header(&header_bytes)?;
        if crit.is_some() {
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

/// Extract `alg` and `enc` from a JWE JOSE header JSON object.
fn parse_alg_enc_header(bytes: &[u8]) -> Result<(String, String), JoseError> {
    let mut reader =
        JsonReader::new(bytes).map_err(|_| JoseError::InvalidToken("malformed header JSON"))?;
    let mut alg = None;
    let mut enc = None;
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
                )
            }
            "enc" => {
                enc = Some(
                    reader
                        .read_string()
                        .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
                )
            }
            _ => reader
                .skip_value()
                .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
        }
    }
    Ok((
        alg.ok_or(JoseError::InvalidToken("missing alg in header"))?,
        enc.ok_or(JoseError::InvalidToken("missing enc in header"))?,
    ))
}

/// Extract `alg` and optional `crit` from a JOSE header JSON object.
fn parse_alg_header(bytes: &[u8]) -> Result<(String, Option<Vec<String>>), JoseError> {
    let mut reader =
        JsonReader::new(bytes).map_err(|_| JoseError::InvalidToken("malformed header JSON"))?;
    let mut alg = None;
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
                )
            }
            "crit" => {
                crit = Some(
                    reader
                        .read_string_array()
                        .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
                )
            }
            _ => reader
                .skip_value()
                .map_err(|_| JoseError::InvalidToken("malformed header JSON"))?,
        }
    }
    Ok((
        alg.ok_or(JoseError::InvalidToken("missing alg in header"))?,
        crit,
    ))
}

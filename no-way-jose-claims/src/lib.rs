//! JWT registered claims and composable validators.
//!
//! Provides [`RegisteredClaims`] (RFC 7519 Section 4.1) with builder methods
//! and ready-made validators: [`HasExpiry`], [`Time`], [`FromIssuer`], and
//! [`ForAudience`]. Validators implement [`Validate`] and compose with
//! `and_then`:
//!
//! ```rust,ignore
//! let v = HasExpiry
//!     .and_then(Time::valid_now())
//!     .and_then(FromIssuer("auth.example.com"))
//!     .and_then(ForAudience("my-api"));
//! ```
//!
//! Timestamp fields (`exp`, `nbf`, `iat`) use [`jiff::Timestamp`] and
//! serialize as integer seconds (`NumericDate`) on the wire.

#![warn(clippy::pedantic)]

pub use jiff;
use no_way_jose_core::JoseError;
use no_way_jose_core::json::{FromJson, JsonReader, JsonWriter, ToJson};
pub use no_way_jose_core::validation::Validate;

/// Registered JWT claims per RFC 7519 Section 4.1.
#[derive(Default, Clone, Debug)]
pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    /// RFC 7519 §4.1.3: may be a single string or an array of strings.
    pub aud: Option<Vec<String>>,
    pub exp: Option<jiff::Timestamp>,
    pub nbf: Option<jiff::Timestamp>,
    pub iat: Option<jiff::Timestamp>,
    pub jti: Option<String>,
}

fn read_timestamp(
    reader: &mut JsonReader,
) -> Result<jiff::Timestamp, Box<dyn core::error::Error + Send + Sync>> {
    let secs = reader.read_i64()?;
    Ok(jiff::Timestamp::from_second(secs)?)
}

impl ToJson for RegisteredClaims {
    fn write_json(&self, buf: &mut Vec<u8>) {
        let mut w = JsonWriter::new();
        if let Some(iss) = &self.iss {
            w.string("iss", iss);
        }
        if let Some(sub) = &self.sub {
            w.string("sub", sub);
        }
        if let Some(aud) = &self.aud {
            w.string_or_array("aud", aud);
        }
        if let Some(exp) = self.exp {
            w.number("exp", exp.as_second());
        }
        if let Some(nbf) = self.nbf {
            w.number("nbf", nbf.as_second());
        }
        if let Some(iat) = self.iat {
            w.number("iat", iat.as_second());
        }
        if let Some(jti) = &self.jti {
            w.string("jti", jti);
        }
        buf.extend_from_slice(&w.finish());
    }
}

impl FromJson for RegisteredClaims {
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, Box<dyn core::error::Error + Send + Sync>> {
        let mut reader = JsonReader::new(bytes)?;
        let mut claims = RegisteredClaims::default();
        while let Some(key) = reader.next_key()? {
            match key {
                "iss" => claims.iss = Some(reader.read_string()?),
                "sub" => claims.sub = Some(reader.read_string()?),
                "aud" => claims.aud = Some(reader.read_string_or_string_array()?),
                "exp" => claims.exp = Some(read_timestamp(&mut reader)?),
                "nbf" => claims.nbf = Some(read_timestamp(&mut reader)?),
                "iat" => claims.iat = Some(read_timestamp(&mut reader)?),
                "jti" => claims.jti = Some(reader.read_string()?),
                _ => reader.skip_value()?,
            }
        }
        Ok(claims)
    }
}

impl RegisteredClaims {
    /// Create claims with `iat` and `nbf` set to `now`, and `exp` set to `now + ttl`.
    ///
    /// # Errors
    /// Returns [`jiff::Error`] if `now + ttl` overflows the timestamp range.
    pub fn new(now: jiff::Timestamp, ttl: jiff::SignedDuration) -> Result<Self, jiff::Error> {
        Ok(Self {
            iss: None,
            sub: None,
            aud: None,
            exp: Some(now.checked_add(ttl)?),
            nbf: Some(now),
            iat: Some(now),
            jti: None,
        })
    }

    #[must_use]
    pub fn from_issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    #[must_use]
    pub fn for_audience(mut self, aud: impl Into<String>) -> Self {
        self.aud.get_or_insert_with(Vec::new).push(aud.into());
        self
    }

    #[must_use]
    pub fn for_subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    #[must_use]
    pub fn with_token_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }
}

// -- Validators --

/// Validates that the `exp` claim is present.
pub struct HasExpiry;

impl Validate for HasExpiry {
    type Claims = RegisteredClaims;

    /// # Errors
    /// Returns [`JoseError::ClaimsError`] if the `exp` claim is missing.
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        if claims.exp.is_none() {
            return Err(JoseError::ClaimsError("missing exp claim"));
        }
        Ok(())
    }
}

/// Validates that the token is not expired (`exp`) and not used before its
/// `nbf` time. Either field may be absent, in which case that check is skipped.
pub struct Time {
    now: jiff::Timestamp,
}

impl Time {
    /// Create a validator using the current system time.
    #[must_use]
    pub fn valid_now() -> Self {
        Self {
            now: jiff::Timestamp::now(),
        }
    }

    /// Create a validator pinned to a specific timestamp (useful for testing).
    #[must_use]
    pub fn valid_at(ts: jiff::Timestamp) -> Self {
        Self { now: ts }
    }
}

impl Validate for Time {
    type Claims = RegisteredClaims;

    /// # Errors
    /// Returns [`JoseError::ClaimsError`] if the token is expired or not yet valid per `exp` / `nbf`.
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        if let Some(exp) = claims.exp
            && exp < self.now
        {
            return Err(JoseError::ClaimsError("token expired"));
        }
        if let Some(nbf) = claims.nbf
            && self.now < nbf
        {
            return Err(JoseError::ClaimsError("token not yet valid"));
        }
        Ok(())
    }
}

/// Validates that `iss` matches the expected issuer string.
pub struct FromIssuer<T: AsRef<str>>(pub T);

impl<T: AsRef<str>> Validate for FromIssuer<T> {
    type Claims = RegisteredClaims;

    /// # Errors
    /// Returns [`JoseError::ClaimsError`] if the `iss` claim does not match the expected issuer.
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        if claims.iss.as_deref() != Some(self.0.as_ref()) {
            return Err(JoseError::ClaimsError("issuer mismatch"));
        }
        Ok(())
    }
}

/// Validates that `aud` contains the expected audience string.
pub struct ForAudience<T: AsRef<str>>(pub T);

impl<T: AsRef<str>> Validate for ForAudience<T> {
    type Claims = RegisteredClaims;

    /// # Errors
    /// Returns [`JoseError::ClaimsError`] if the `aud` claim does not include the expected audience.
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        match &claims.aud {
            Some(auds) if auds.iter().any(|a| a == self.0.as_ref()) => Ok(()),
            _ => Err(JoseError::ClaimsError("audience mismatch")),
        }
    }
}

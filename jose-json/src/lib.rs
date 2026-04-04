pub use jiff;
pub use jose_core::validation::Validate;

use jose_core::JoseError;
use jose_core::json::{FromJson, JsonReader, JsonWriter, ToJson};

/// Registered JWT claims per RFC 7519 Section 4.1.
///
/// Timestamps are NumericDate (seconds since epoch).
#[derive(Default, Clone, Debug)]
pub struct RegisteredClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    /// RFC 7519 §4.1.3: may be a single string or an array of strings.
    pub aud: Option<Vec<String>>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
}

impl ToJson for RegisteredClaims {
    fn to_json_bytes(&self) -> Vec<u8> {
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
            w.number("exp", exp);
        }
        if let Some(nbf) = self.nbf {
            w.number("nbf", nbf);
        }
        if let Some(iat) = self.iat {
            w.number("iat", iat);
        }
        if let Some(jti) = &self.jti {
            w.string("jti", jti);
        }
        w.finish()
    }
}

impl FromJson for RegisteredClaims {
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, JoseError> {
        let mut reader = JsonReader::new(bytes)?;
        let mut claims = RegisteredClaims::default();
        while let Some(key) = reader.next_key()? {
            match key {
                "iss" => claims.iss = Some(reader.read_string()?),
                "sub" => claims.sub = Some(reader.read_string()?),
                "aud" => claims.aud = Some(reader.read_string_or_string_array()?),
                "exp" => claims.exp = Some(reader.read_i64()?),
                "nbf" => claims.nbf = Some(reader.read_i64()?),
                "iat" => claims.iat = Some(reader.read_i64()?),
                "jti" => claims.jti = Some(reader.read_string()?),
                _ => reader.skip_value()?,
            }
        }
        Ok(claims)
    }
}

impl RegisteredClaims {
    pub fn new(now: jiff::Timestamp, ttl: jiff::SignedDuration) -> Self {
        let now_secs = now.as_second();
        let exp_secs = now.checked_add(ttl).expect("TTL overflow").as_second();
        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: Some(exp_secs),
            nbf: Some(now_secs),
            iat: Some(now_secs),
            jti: None,
        }
    }

    pub fn from_issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn for_audience(mut self, aud: impl Into<String>) -> Self {
        self.aud.get_or_insert_with(Vec::new).push(aud.into());
        self
    }

    pub fn for_subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    pub fn with_token_id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }
}

// -- Validators --

pub struct HasExpiry;

impl Validate for HasExpiry {
    type Claims = RegisteredClaims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        if claims.exp.is_none() {
            return Err(JoseError::ClaimsError("missing exp claim"));
        }
        Ok(())
    }
}

pub struct Time {
    now: i64,
}

impl Time {
    pub fn valid_now() -> Self {
        Self {
            now: jiff::Timestamp::now().as_second(),
        }
    }

    pub fn valid_at(ts: jiff::Timestamp) -> Self {
        Self {
            now: ts.as_second(),
        }
    }
}

impl Validate for Time {
    type Claims = RegisteredClaims;

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

pub struct FromIssuer<T: AsRef<str>>(pub T);

impl<T: AsRef<str>> Validate for FromIssuer<T> {
    type Claims = RegisteredClaims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        if claims.iss.as_deref() != Some(self.0.as_ref()) {
            return Err(JoseError::ClaimsError("issuer mismatch"));
        }
        Ok(())
    }
}

pub struct ForAudience<T: AsRef<str>>(pub T);

impl<T: AsRef<str>> Validate for ForAudience<T> {
    type Claims = RegisteredClaims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        match &claims.aud {
            Some(auds) if auds.iter().any(|a| a == self.0.as_ref()) => Ok(()),
            _ => Err(JoseError::ClaimsError("audience mismatch")),
        }
    }
}

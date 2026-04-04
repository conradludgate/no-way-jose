pub use jiff;
pub use jose_core::validation::Validate;

use jose_core::JoseError;

/// Registered JWT claims per RFC 7519 Section 4.1.
///
/// Timestamps are NumericDate (seconds since epoch).
#[derive(Default, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RegisteredClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// RFC 7519 §4.1.3: may be a single string or an array of strings.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "one_or_many::serialize",
        deserialize_with = "one_or_many::deserialize"
    )]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

mod one_or_many {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<String>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            None => serializer.serialize_none(),
            Some(v) if v.len() == 1 => serializer.serialize_str(&v[0]),
            Some(v) => v.serialize(serializer),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<String>>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }

        Option::<OneOrMany>::deserialize(deserializer).map(|opt| match opt {
            None => None,
            Some(OneOrMany::One(s)) => Some(vec![s]),
            Some(OneOrMany::Many(v)) => Some(v),
        })
    }
}

impl RegisteredClaims {
    pub fn new(now: jiff::Timestamp, ttl: jiff::SignedDuration) -> Self {
        let now_secs = now.as_second();
        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: Some(now_secs + ttl.as_secs()),
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
            return Err(JoseError::ClaimsError);
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
            return Err(JoseError::ClaimsError);
        }
        if let Some(nbf) = claims.nbf
            && self.now < nbf
        {
            return Err(JoseError::ClaimsError);
        }
        Ok(())
    }
}

pub struct FromIssuer<T: AsRef<str>>(pub T);

impl<T: AsRef<str>> Validate for FromIssuer<T> {
    type Claims = RegisteredClaims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        if claims.iss.as_deref() != Some(self.0.as_ref()) {
            return Err(JoseError::ClaimsError);
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
            _ => Err(JoseError::ClaimsError),
        }
    }
}

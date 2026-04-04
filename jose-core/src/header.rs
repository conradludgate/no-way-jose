use alloc::string::String;

use crate::JoseError;

/// Borrowed view over a decoded JOSE header.
/// Deserializes on demand from the raw JSON.
#[derive(serde::Deserialize, Debug)]
pub struct Header<'a> {
    pub alg: &'a str,
    #[serde(default)]
    pub enc: Option<&'a str>,
    #[serde(default)]
    pub kid: Option<&'a str>,
    #[serde(default)]
    pub typ: Option<&'a str>,
    #[serde(default)]
    pub cty: Option<&'a str>,
}

/// Builds a JOSE header as a base64url-encoded string.
pub struct HeaderBuilder {
    alg: &'static str,
    kid: Option<String>,
    typ: Option<String>,
    extra: alloc::vec::Vec<(String, String)>,
}

impl HeaderBuilder {
    pub fn new(alg: &'static str) -> Self {
        HeaderBuilder {
            alg,
            kid: None,
            typ: None,
            extra: alloc::vec::Vec::new(),
        }
    }

    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.typ = Some(typ.into());
        self
    }

    /// Build and return the base64url-encoded header.
    pub fn build(self) -> String {
        let mut json = alloc::format!(r#"{{"alg":"{}""#, self.alg);
        if let Some(kid) = &self.kid {
            json.push_str(&alloc::format!(r#","kid":"{}""#, kid));
        }
        if let Some(typ) = &self.typ {
            json.push_str(&alloc::format!(r#","typ":"{}""#, typ));
        }
        for (k, v) in &self.extra {
            json.push_str(&alloc::format!(r#","{}":"{}""#, k, v));
        }
        json.push('}');
        crate::base64url::encode(json.as_bytes())
    }
}

/// Parse a header from a base64url-encoded string.
pub fn parse_header(header_b64: &str) -> Result<Header<'_>, JoseError> {
    // We need to decode first, then deserialize. But the lifetime of the
    // decoded bytes is owned, so we can't return a borrowing Header.
    // Instead, callers should use `parse_header_owned`.
    let _ = header_b64;
    Err(JoseError::InvalidToken)
}

/// Parse a header, returning owned data.
pub fn parse_header_owned(header_b64: &str) -> Result<OwnedHeader, JoseError> {
    let bytes = crate::base64url::decode(header_b64)?;
    serde_json::from_slice(&bytes).map_err(|_| JoseError::InvalidToken)
}

/// Owned version of Header for when the source bytes aren't available.
#[derive(serde::Deserialize, Debug)]
pub struct OwnedHeader {
    pub alg: String,
    #[serde(default)]
    pub enc: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub typ: Option<String>,
    #[serde(default)]
    pub cty: Option<String>,
}

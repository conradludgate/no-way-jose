use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::JoseError;

/// Borrowed view over a decoded JOSE header.
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
    #[serde(default)]
    pub crit: Option<alloc::vec::Vec<&'a str>>,
}

/// Builds a JOSE header and returns it as a base64url-encoded string.
pub struct HeaderBuilder {
    header: BuilderHeader,
}

#[derive(serde::Serialize)]
struct BuilderHeader {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, String>,
}

impl HeaderBuilder {
    pub fn new(alg: &'static str) -> Self {
        HeaderBuilder {
            header: BuilderHeader {
                alg,
                kid: None,
                typ: None,
                extra: BTreeMap::new(),
            },
        }
    }

    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.header.kid = Some(kid.into());
        self
    }

    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.header.typ = Some(typ.into());
        self
    }

    pub fn build(self) -> String {
        let json = serde_json::to_vec(&self.header).expect("header serialization cannot fail");
        crate::base64url::encode(&json)
    }
}

/// Parse a base64url-encoded header into owned fields.
pub fn parse_header_owned(header_b64: &str) -> Result<OwnedHeader, JoseError> {
    let bytes = crate::base64url::decode(header_b64)?;
    serde_json::from_slice(&bytes).map_err(|_| JoseError::InvalidToken("malformed header JSON"))
}

/// Owned version of a decoded JOSE header.
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
    #[serde(default)]
    pub crit: Option<alloc::vec::Vec<String>>,
}

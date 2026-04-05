use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{JoseError, JoseResult, TokenFormatError};
use crate::json::{FromJson, JsonReader, JsonWriter};

/// Builds a JOSE header and returns it as a base64url-encoded string.
pub struct HeaderBuilder {
    header: BuilderHeader,
}

struct BuilderHeader {
    alg: &'static str,
    enc: Option<&'static str>,
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
    extra: BTreeMap<String, String>,
}

impl HeaderBuilder {
    #[must_use]
    pub fn new(alg: &'static str) -> Self {
        HeaderBuilder {
            header: BuilderHeader {
                alg,
                enc: None,
                kid: None,
                typ: None,
                cty: None,
                extra: BTreeMap::new(),
            },
        }
    }

    #[must_use]
    pub fn enc(mut self, enc: &'static str) -> Self {
        self.header.enc = Some(enc);
        self
    }

    #[must_use]
    pub fn kid(mut self, kid: impl Into<String>) -> Self {
        self.header.kid = Some(kid.into());
        self
    }

    #[must_use]
    pub fn typ(mut self, typ: impl Into<String>) -> Self {
        self.header.typ = Some(typ.into());
        self
    }

    #[must_use]
    pub fn cty(mut self, cty: impl Into<String>) -> Self {
        self.header.cty = Some(cty.into());
        self
    }

    #[must_use]
    pub fn build(self) -> String {
        let json = self.header.to_json_bytes();
        crate::base64url::encode(&json)
    }
}

impl BuilderHeader {
    fn to_json_bytes(&self) -> Vec<u8> {
        let mut w = JsonWriter::new();
        w.string("alg", self.alg);
        if let Some(enc) = self.enc {
            w.string("enc", enc);
        }
        if let Some(kid) = &self.kid {
            w.string("kid", kid);
        }
        if let Some(typ) = &self.typ {
            w.string("typ", typ);
        }
        if let Some(cty) = &self.cty {
            w.string("cty", cty);
        }
        for (k, v) in &self.extra {
            w.string(k, v);
        }
        w.finish()
    }
}

/// Parse a base64url-encoded header into owned fields.
///
/// # Errors
/// Returns [`JoseError::Base64Decode`] or [`JoseError::MalformedToken`] on failure.
pub fn parse_header_owned(header_b64: &str) -> JoseResult<OwnedHeader> {
    let bytes = crate::base64url::decode(header_b64)?;
    OwnedHeader::from_json_bytes(&bytes)
        .map_err(|e| error_stack::Report::new(JoseError::MalformedToken).attach(e))
}

/// Owned version of a decoded JOSE header.
#[derive(Debug)]
pub struct OwnedHeader {
    pub alg: String,
    pub enc: Option<String>,
    pub kid: Option<String>,
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub crit: Option<Vec<String>>,
}

impl FromJson for OwnedHeader {
    /// # Errors
    /// Returns an error if the JSON is malformed or `alg` is missing.
    fn from_json_bytes(
        bytes: &[u8],
    ) -> Result<Self, alloc::boxed::Box<dyn core::error::Error + Send + Sync>> {
        let mut reader = JsonReader::new(bytes)?;
        let mut alg = None;
        let mut enc = None;
        let mut kid = None;
        let mut typ = None;
        let mut cty = None;
        let mut crit = None;
        while let Some(key) = reader.next_key()? {
            match key {
                "alg" => alg = Some(reader.read_string()?),
                "enc" => enc = Some(reader.read_string()?),
                "kid" => kid = Some(reader.read_string()?),
                "typ" => typ = Some(reader.read_string()?),
                "cty" => cty = Some(reader.read_string()?),
                "crit" => crit = Some(reader.read_string_array()?),
                _ => reader.skip_value()?,
            }
        }
        Ok(OwnedHeader {
            alg: alg.ok_or(TokenFormatError::MissingAlg)?,
            enc,
            kid,
            typ,
            cty,
            crit,
        })
    }
}

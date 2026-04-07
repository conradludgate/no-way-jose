use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use error_stack::Report;
use no_way_jose_core::error::{JoseError, JoseResult};
use no_way_jose_core::json::{JsonReader, JsonWriter};

/// Ephemeral public key fields extracted from or serialized to the JWE header.
pub(crate) struct EpkFields {
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: Vec<u8>,
    pub y: Option<Vec<u8>>,
}

impl EpkFields {
    /// Serialize as a raw JSON object (ready for `raw_value`).
    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::new();
        w.string("kty", self.kty);
        w.string("crv", self.crv);
        w.string("x", &Base64UrlUnpadded::encode_string(&self.x));
        if let Some(y) = &self.y {
            w.string("y", &Base64UrlUnpadded::encode_string(y));
        }
        w.finish()
    }

    /// Parse from the `epk` field of a JWE header (raw header JSON bytes).
    pub fn from_header(header: &[u8]) -> JoseResult<Self> {
        let mut reader =
            JsonReader::new(header).map_err(|_| Report::new(JoseError::MalformedToken))?;

        while let Some(key) = reader
            .next_key()
            .map_err(|_| Report::new(JoseError::MalformedToken))?
        {
            if key == "epk" {
                let before = reader.remaining();
                reader
                    .skip_value()
                    .map_err(|_| Report::new(JoseError::MalformedToken))?;
                let consumed = before.len() - reader.remaining().len();
                let epk_bytes = &before[..consumed];
                return Self::parse_epk_object(epk_bytes);
            }
            reader
                .skip_value()
                .map_err(|_| Report::new(JoseError::MalformedToken))?;
        }
        Err(Report::new(JoseError::MalformedToken))
    }

    fn parse_epk_object(bytes: &[u8]) -> JoseResult<Self> {
        let mut reader =
            JsonReader::new(bytes).map_err(|_| Report::new(JoseError::MalformedToken))?;
        let mut kty: Option<String> = None;
        let mut crv: Option<String> = None;
        let mut x: Option<String> = None;
        let mut y: Option<String> = None;

        while let Some(key) = reader
            .next_key()
            .map_err(|_| Report::new(JoseError::MalformedToken))?
        {
            match key {
                "kty" => {
                    kty = Some(
                        reader
                            .read_string()
                            .map_err(|_| Report::new(JoseError::MalformedToken))?,
                    );
                }
                "crv" => {
                    crv = Some(
                        reader
                            .read_string()
                            .map_err(|_| Report::new(JoseError::MalformedToken))?,
                    );
                }
                "x" => {
                    x = Some(
                        reader
                            .read_string()
                            .map_err(|_| Report::new(JoseError::MalformedToken))?,
                    );
                }
                "y" => {
                    y = Some(
                        reader
                            .read_string()
                            .map_err(|_| Report::new(JoseError::MalformedToken))?,
                    );
                }
                _ => reader
                    .skip_value()
                    .map_err(|_| Report::new(JoseError::MalformedToken))?,
            }
        }

        let crv_str = crv.ok_or(Report::new(JoseError::MalformedToken))?;
        let x_b64 = x.ok_or(Report::new(JoseError::MalformedToken))?;

        let (kty_static, crv_static): (&'static str, &'static str) = match crv_str.as_str() {
            "P-256" => {
                if let Some(ref kt) = kty
                    && kt != "EC"
                {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                ("EC", "P-256")
            }
            "P-384" => {
                if let Some(ref kt) = kty
                    && kt != "EC"
                {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                ("EC", "P-384")
            }
            "X25519" => {
                if let Some(ref kt) = kty
                    && kt != "OKP"
                {
                    return Err(Report::new(JoseError::MalformedToken));
                }
                ("OKP", "X25519")
            }
            _ => return Err(Report::new(JoseError::MalformedToken)),
        };

        let x_bytes = Base64UrlUnpadded::decode_vec(&x_b64)
            .map_err(|_| Report::new(JoseError::MalformedToken))?;
        let y_bytes = y
            .map(|b| {
                Base64UrlUnpadded::decode_vec(&b)
                    .map_err(|_| Report::new(JoseError::MalformedToken))
            })
            .transpose()?;

        if crv_static == "X25519" && y_bytes.is_some() {
            return Err(Report::new(JoseError::MalformedToken));
        }

        Ok(EpkFields {
            kty: kty_static,
            crv: crv_static,
            x: x_bytes,
            y: y_bytes,
        })
    }

    pub fn to_p256_public_key(&self) -> JoseResult<p256::PublicKey> {
        if self.crv != "P-256" {
            return Err(Report::new(JoseError::MalformedToken));
        }
        let y = self
            .y
            .as_ref()
            .ok_or(Report::new(JoseError::MalformedToken))?;

        let mut uncompressed = Vec::with_capacity(1 + self.x.len() + y.len());
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&self.x);
        uncompressed.extend_from_slice(y);

        p256::PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|_| Report::new(JoseError::MalformedToken))
    }

    pub fn to_p384_public_key(&self) -> JoseResult<p384::PublicKey> {
        if self.crv != "P-384" {
            return Err(Report::new(JoseError::MalformedToken));
        }
        let y = self
            .y
            .as_ref()
            .ok_or(Report::new(JoseError::MalformedToken))?;

        let mut uncompressed = Vec::with_capacity(1 + self.x.len() + y.len());
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&self.x);
        uncompressed.extend_from_slice(y);

        p384::PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|_| Report::new(JoseError::MalformedToken))
    }

    pub fn to_x25519_public_key(&self) -> JoseResult<x25519_dalek::PublicKey> {
        if self.crv != "X25519" {
            return Err(Report::new(JoseError::MalformedToken));
        }
        let x_arr: [u8; 32] = self
            .x
            .as_slice()
            .try_into()
            .map_err(|_| Report::new(JoseError::MalformedToken))?;
        Ok(x25519_dalek::PublicKey::from(x_arr))
    }
}

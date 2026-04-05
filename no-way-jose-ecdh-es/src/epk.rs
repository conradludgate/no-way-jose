use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use no_way_jose_core::JoseError;
use no_way_jose_core::json::{JsonReader, JsonWriter};

/// Ephemeral public key fields extracted from or serialized to the JWE header.
pub(crate) struct EpkFields {
    pub crv: &'static str,
    pub x: Vec<u8>,
    pub y: Option<Vec<u8>>,
}

impl EpkFields {
    /// Serialize as a raw JSON object (ready for `raw_value`).
    pub fn to_json_bytes(&self) -> Vec<u8> {
        let mut w = JsonWriter::new();
        w.string("kty", "EC");
        w.string("crv", self.crv);
        w.string("x", &Base64UrlUnpadded::encode_string(&self.x));
        if let Some(y) = &self.y {
            w.string("y", &Base64UrlUnpadded::encode_string(y));
        }
        w.finish()
    }

    /// Parse from the `epk` field of a JWE header (raw header JSON bytes).
    pub fn from_header(header: &[u8]) -> Result<Self, JoseError> {
        let mut reader =
            JsonReader::new(header).map_err(|_| JoseError::InvalidToken("malformed header"))?;

        while let Some(key) = reader
            .next_key()
            .map_err(|_| JoseError::InvalidToken("malformed header"))?
        {
            if key == "epk" {
                let start = reader.current_pos();
                reader
                    .skip_value()
                    .map_err(|_| JoseError::InvalidToken("malformed epk"))?;
                let end = reader.current_pos();
                let epk_bytes = &reader.input_bytes()[start..end];
                return Self::parse_epk_object(epk_bytes);
            }
            reader
                .skip_value()
                .map_err(|_| JoseError::InvalidToken("malformed header"))?;
        }
        Err(JoseError::InvalidToken("missing epk in header"))
    }

    fn parse_epk_object(bytes: &[u8]) -> Result<Self, JoseError> {
        let mut reader =
            JsonReader::new(bytes).map_err(|_| JoseError::InvalidToken("malformed epk object"))?;
        let mut crv: Option<String> = None;
        let mut x: Option<String> = None;
        let mut y: Option<String> = None;

        while let Some(key) = reader
            .next_key()
            .map_err(|_| JoseError::InvalidToken("malformed epk"))?
        {
            match key {
                "crv" => {
                    crv = Some(
                        reader
                            .read_string()
                            .map_err(|_| JoseError::InvalidToken("malformed epk"))?,
                    );
                }
                "x" => {
                    x = Some(
                        reader
                            .read_string()
                            .map_err(|_| JoseError::InvalidToken("malformed epk"))?,
                    );
                }
                "y" => {
                    y = Some(
                        reader
                            .read_string()
                            .map_err(|_| JoseError::InvalidToken("malformed epk"))?,
                    );
                }
                _ => reader
                    .skip_value()
                    .map_err(|_| JoseError::InvalidToken("malformed epk"))?,
            }
        }

        let crv_str = crv.ok_or(JoseError::InvalidToken("missing crv in epk"))?;
        let x_b64 = x.ok_or(JoseError::InvalidToken("missing x in epk"))?;

        let crv_static: &'static str = match crv_str.as_str() {
            "P-256" => "P-256",
            "P-384" => "P-384",
            _ => return Err(JoseError::InvalidToken("unsupported curve in epk")),
        };

        let x_bytes = Base64UrlUnpadded::decode_vec(&x_b64)
            .map_err(|_| JoseError::InvalidToken("invalid base64url in epk x"))?;
        let y_bytes = y
            .map(|b| {
                Base64UrlUnpadded::decode_vec(&b)
                    .map_err(|_| JoseError::InvalidToken("invalid base64url in epk y"))
            })
            .transpose()?;

        Ok(EpkFields {
            crv: crv_static,
            x: x_bytes,
            y: y_bytes,
        })
    }

    pub fn to_p256_public_key(&self) -> Result<p256::PublicKey, JoseError> {
        if self.crv != "P-256" {
            return Err(JoseError::InvalidToken("curve mismatch: expected P-256"));
        }
        let y = self
            .y
            .as_ref()
            .ok_or(JoseError::InvalidToken("missing y coordinate for P-256"))?;

        let mut uncompressed = Vec::with_capacity(1 + self.x.len() + y.len());
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&self.x);
        uncompressed.extend_from_slice(y);

        p256::PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|_| JoseError::InvalidToken("invalid P-256 public key in epk"))
    }

    pub fn to_p384_public_key(&self) -> Result<p384::PublicKey, JoseError> {
        if self.crv != "P-384" {
            return Err(JoseError::InvalidToken("curve mismatch: expected P-384"));
        }
        let y = self
            .y
            .as_ref()
            .ok_or(JoseError::InvalidToken("missing y coordinate for P-384"))?;

        let mut uncompressed = Vec::with_capacity(1 + self.x.len() + y.len());
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&self.x);
        uncompressed.extend_from_slice(y);

        p384::PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|_| JoseError::InvalidToken("invalid P-384 public key in epk"))
    }
}

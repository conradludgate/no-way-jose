use alloc::string::String;
use alloc::vec::Vec;

use error_stack::ResultExt;

use crate::error::{JoseError, JoseResult, JsonError};

/// Serialize a value as compact JSON.
pub trait ToJson {
    /// Write this value's JSON representation into `buf`.
    fn write_json(&self, buf: &mut String);

    /// Convenience wrapper that allocates and returns the JSON string.
    fn to_json(&self) -> String {
        let mut buf = String::new();
        self.write_json(&mut buf);
        buf
    }
}

/// Deserialize a value from compact JSON bytes.
pub trait FromJson: Sized {
    /// # Errors
    /// Returns an error if the bytes are not valid JSON for this type.
    fn from_json_bytes(
        bytes: &[u8],
    ) -> Result<Self, alloc::boxed::Box<dyn core::error::Error + Send + Sync>>;
}

/// Opaque JSON payload — stores raw bytes without parsing.
pub struct RawJson(pub String);

impl ToJson for RawJson {
    fn write_json(&self, buf: &mut String) {
        buf.push_str(&self.0);
    }
}

impl FromJson for RawJson {
    /// # Errors
    /// This implementation never fails.
    fn from_json_bytes(
        bytes: &[u8],
    ) -> Result<Self, alloc::boxed::Box<dyn core::error::Error + Send + Sync>> {
        Ok(RawJson(String::from(core::str::from_utf8(bytes)?)))
    }
}

// -- Writer --

/// Builds a compact JSON object incrementally.
pub struct JsonWriter {
    buf: String,
    first: bool,
}

impl Default for JsonWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonWriter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: String::from("{"),
            first: true,
        }
    }

    fn write_key(&mut self, key: &str) {
        if !self.first {
            self.buf.push(',');
        }
        self.first = false;
        write_escaped_string(&mut self.buf, key);
        self.buf.push(':');
    }

    pub fn string(&mut self, key: &str, value: &str) {
        self.write_key(key);
        write_escaped_string(&mut self.buf, value);
    }

    pub fn number(&mut self, key: &str, value: i64) {
        self.write_key(key);
        let _ = alloc::fmt::Write::write_fmt(&mut self.buf, format_args!("{value}"));
    }

    pub fn bool(&mut self, key: &str, value: bool) {
        self.write_key(key);
        self.buf.push_str(if value { "true" } else { "false" });
    }

    /// Write a single string when `values.len() == 1`, otherwise an array.
    pub fn string_or_array(&mut self, key: &str, values: &[String]) {
        self.write_key(key);
        if values.len() == 1 {
            write_escaped_string(&mut self.buf, &values[0]);
        } else {
            self.buf.push('[');
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    self.buf.push(',');
                }
                write_escaped_string(&mut self.buf, v);
            }
            self.buf.push(']');
        }
    }

    /// Write a pre-formed raw JSON value (no escaping or quoting applied).
    pub fn raw_value(&mut self, key: &str, raw_json: &str) {
        self.write_key(key);
        self.buf.push_str(raw_json);
    }

    #[must_use]
    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// Write a JSON object key followed by `:` into `buf`. Used by header rebuild logic.
pub(crate) fn write_json_key(buf: &mut String, key: &str) {
    write_escaped_string(buf, key);
    buf.push(':');
}

fn write_escaped_string(buf: &mut String, s: &str) {
    buf.push('"');
    for &b in s.as_bytes() {
        match b {
            b'"' => buf.push_str("\\\""),
            b'\\' => buf.push_str("\\\\"),
            b'\n' => buf.push_str("\\n"),
            b'\r' => buf.push_str("\\r"),
            b'\t' => buf.push_str("\\t"),
            b if b < 0x20 => {
                buf.push_str("\\u00");
                buf.push(char::from(hex_nibble(b >> 4)));
                buf.push(char::from(hex_nibble(b & 0xf)));
            }
            _ => buf.push(char::from(b)),
        }
    }
    buf.push('"');
}

fn hex_nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

// -- Reader --

/// Scans a compact JSON object, yielding key-value entries for field extraction.
///
/// Expects strictly compact JSON — no whitespace between tokens.
pub struct JsonReader<'a> {
    input: &'a [u8],
    pos: usize,
    first: bool,
}

impl<'a> JsonReader<'a> {
    /// # Errors
    /// Returns [`JsonError::ExpectedObject`] if the input does not start with `{`.
    pub fn new(input: &'a [u8]) -> Result<Self, JsonError> {
        if input.first() != Some(&b'{') {
            return Err(JsonError::ExpectedObject);
        }
        Ok(Self {
            input,
            pos: 1,
            first: true,
        })
    }

    /// Current byte offset into the input buffer.
    #[must_use]
    pub fn current_pos(&self) -> usize {
        self.pos
    }

    /// The raw input slice.
    #[must_use]
    pub fn input_bytes(&self) -> &'a [u8] {
        self.input
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() != Some(byte) {
            return Err(JsonError::UnexpectedByte);
        }
        self.pos += 1;
        Ok(())
    }

    /// Returns the next object key, or `None` when `}` is reached.
    /// Keys are borrowed from the input — escape sequences in keys are rejected.
    ///
    /// # Errors
    /// Returns [`JsonError`] on malformed JSON, trailing data, or invalid UTF-8.
    pub fn next_key(&mut self) -> Result<Option<&'a str>, JsonError> {
        if self.peek() == Some(b'}') {
            self.pos += 1;
            if self.pos != self.input.len() {
                return Err(JsonError::TrailingData);
            }
            return Ok(None);
        }
        if !self.first {
            self.expect(b',')?;
        }
        self.first = false;
        self.expect(b'"')?;
        let start = self.pos;
        loop {
            match self.input.get(self.pos) {
                None => return Err(JsonError::UnterminatedJson),
                Some(b'"') => {
                    let key = core::str::from_utf8(&self.input[start..self.pos])
                        .map_err(|_| JsonError::InvalidKey)?;
                    self.pos += 1;
                    self.expect(b':')?;
                    return Ok(Some(key));
                }
                Some(b'\\') => {
                    return Err(JsonError::InvalidKey);
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    /// # Errors
    /// Returns [`JsonError`] on malformed JSON, invalid escapes, or invalid UTF-8.
    pub fn read_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut result = String::new();
        let mut run_start = self.pos;
        loop {
            match self.input.get(self.pos) {
                None => return Err(JsonError::InvalidString),
                Some(b'"') => {
                    if run_start < self.pos {
                        let s = core::str::from_utf8(&self.input[run_start..self.pos])
                            .map_err(|_| JsonError::InvalidString)?;
                        result.push_str(s);
                    }
                    self.pos += 1;
                    return Ok(result);
                }
                Some(b'\\') => {
                    if run_start < self.pos {
                        let s = core::str::from_utf8(&self.input[run_start..self.pos])
                            .map_err(|_| JsonError::InvalidString)?;
                        result.push_str(s);
                    }
                    self.pos += 1;
                    match self.input.get(self.pos) {
                        Some(b'"') => {
                            result.push('"');
                            self.pos += 1;
                        }
                        Some(b'\\') => {
                            result.push('\\');
                            self.pos += 1;
                        }
                        Some(b'/') => {
                            result.push('/');
                            self.pos += 1;
                        }
                        Some(b'n') => {
                            result.push('\n');
                            self.pos += 1;
                        }
                        Some(b'r') => {
                            result.push('\r');
                            self.pos += 1;
                        }
                        Some(b't') => {
                            result.push('\t');
                            self.pos += 1;
                        }
                        Some(b'b') => {
                            result.push('\u{08}');
                            self.pos += 1;
                        }
                        Some(b'f') => {
                            result.push('\u{0C}');
                            self.pos += 1;
                        }
                        Some(b'u') => {
                            self.pos += 1;
                            let ch = self.read_unicode_escape()?;
                            result.push(ch);
                        }
                        _ => return Err(JsonError::InvalidEscape),
                    }
                    run_start = self.pos;
                }
                Some(&b) if b < 0x20 => {
                    return Err(JsonError::InvalidString);
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    /// # Errors
    /// Returns [`JsonError`] if the value is not a valid JSON integer in range.
    pub fn read_i64(&mut self) -> Result<i64, JsonError> {
        let start = self.pos;
        if self.input.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.input.get(self.pos) {
            Some(b'0') => {
                self.pos += 1;
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(JsonError::InvalidNumber),
        }
        let s = core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| JsonError::InvalidNumber)?;
        s.parse::<i64>().map_err(|_| JsonError::NumberOutOfRange)
    }

    /// # Errors
    /// Returns [`JsonError::ExpectedBoolean`] if the value is not `true` or `false`.
    pub fn read_bool(&mut self) -> Result<bool, JsonError> {
        if self.input.get(self.pos..self.pos + 4) == Some(b"true") {
            self.pos += 4;
            Ok(true)
        } else if self.input.get(self.pos..self.pos + 5) == Some(b"false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(JsonError::ExpectedBoolean)
        }
    }

    /// Read a value that is either a single JSON string or an array of strings.
    ///
    /// # Errors
    /// Returns [`JsonError`] if the value is neither a string nor a string array.
    pub fn read_string_or_string_array(&mut self) -> Result<Vec<String>, JsonError> {
        match self.peek() {
            Some(b'"') => {
                let s = self.read_string()?;
                Ok(alloc::vec![s])
            }
            Some(b'[') => self.read_string_array(),
            _ => Err(JsonError::ExpectedStringOrArray),
        }
    }

    /// # Errors
    /// Returns [`JsonError`] on malformed array syntax or string values.
    pub fn read_string_array(&mut self) -> Result<Vec<String>, JsonError> {
        self.expect(b'[')?;
        let mut result = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(result);
        }
        loop {
            result.push(self.read_string()?);
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(result);
                }
                _ => return Err(JsonError::InvalidArraySyntax),
            }
        }
    }

    /// Skip one JSON value of any type (string, number, bool, null, object, array).
    ///
    /// # Errors
    /// Returns [`JsonError`] if the value is malformed or unterminated.
    pub fn skip_value(&mut self) -> Result<(), JsonError> {
        match self.peek() {
            Some(b'"') => {
                self.skip_string()?;
            }
            Some(b'{' | b'[') => self.skip_nested()?,
            Some(b't') => {
                if self.input.get(self.pos..self.pos + 4) != Some(b"true") {
                    return Err(JsonError::InvalidValue);
                }
                self.pos += 4;
            }
            Some(b'f') => {
                if self.input.get(self.pos..self.pos + 5) != Some(b"false") {
                    return Err(JsonError::InvalidValue);
                }
                self.pos += 5;
            }
            Some(b'n') => {
                if self.input.get(self.pos..self.pos + 4) != Some(b"null") {
                    return Err(JsonError::InvalidValue);
                }
                self.pos += 4;
            }
            Some(b'-' | b'0'..=b'9') => self.skip_number()?,
            _ => return Err(JsonError::InvalidValue),
        }
        Ok(())
    }

    fn skip_string(&mut self) -> Result<(), JsonError> {
        self.pos += 1; // opening quote
        loop {
            match self.input.get(self.pos) {
                None => return Err(JsonError::InvalidString),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(());
                }
                Some(b'\\') => {
                    self.pos += 2;
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn skip_nested(&mut self) -> Result<(), JsonError> {
        let mut depth = 0u32;
        loop {
            match self.input.get(self.pos) {
                None => return Err(JsonError::UnterminatedJson),
                Some(b'"') => {
                    self.skip_string()?;
                }
                Some(b'{' | b'[') => {
                    depth += 1;
                    self.pos += 1;
                }
                Some(b'}' | b']') => {
                    depth -= 1;
                    self.pos += 1;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    fn skip_number(&mut self) -> Result<(), JsonError> {
        if self.input.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        if !matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
            return Err(JsonError::InvalidNumber);
        }
        while matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.input.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            while matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.input.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.input.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            while matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(())
    }

    fn read_unicode_escape(&mut self) -> Result<char, JsonError> {
        let high = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            if self.input.get(self.pos..self.pos + 2) != Some(b"\\u") {
                return Err(JsonError::InvalidUnicodeEscape);
            }
            self.pos += 2;
            let low = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JsonError::InvalidUnicodeEscape);
            }
            let cp = 0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
            char::from_u32(cp).ok_or(JsonError::InvalidUnicodeEscape)
        } else if (0xDC00..=0xDFFF).contains(&high) {
            Err(JsonError::InvalidUnicodeEscape)
        } else {
            char::from_u32(u32::from(high)).ok_or(JsonError::InvalidUnicodeEscape)
        }
    }

    fn read_hex4(&mut self) -> Result<u16, JsonError> {
        if self.pos + 4 > self.input.len() {
            return Err(JsonError::InvalidUnicodeEscape);
        }
        let mut value = 0u16;
        for i in 0..4 {
            let digit = self.input[self.pos + i];
            let n = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(JsonError::InvalidUnicodeEscape),
            };
            value = value * 16 + u16::from(n);
        }
        self.pos += 4;
        Ok(value)
    }
}

/// Read a string-valued field from a compact JSON header object.
///
/// # Errors
/// Returns [`JoseError::MalformedToken`] if the header is malformed or the field is missing.
pub fn read_header_string(header: &[u8], field: &str) -> JoseResult<String> {
    let mut reader = JsonReader::new(header).change_context(JoseError::MalformedToken)?;
    while let Some(key) = reader
        .next_key()
        .change_context(JoseError::MalformedToken)?
    {
        if key == field {
            return reader
                .read_string()
                .change_context(JoseError::MalformedToken);
        }
        reader
            .skip_value()
            .change_context(JoseError::MalformedToken)?;
    }
    Err(error_stack::Report::new(JsonError::MissingField).change_context(JoseError::MalformedToken))
}

/// Read an integer-valued field from a compact JSON header object.
///
/// # Errors
/// Returns [`JoseError::MalformedToken`] if the header is malformed, the field is missing, or the value is not an integer.
pub fn read_header_i64(header: &[u8], field: &str) -> JoseResult<i64> {
    let mut reader = JsonReader::new(header).change_context(JoseError::MalformedToken)?;
    while let Some(key) = reader
        .next_key()
        .change_context(JoseError::MalformedToken)?
    {
        if key == field {
            return reader.read_i64().change_context(JoseError::MalformedToken);
        }
        reader
            .skip_value()
            .change_context(JoseError::MalformedToken)?;
    }
    Err(error_stack::Report::new(JsonError::MissingField).change_context(JoseError::MalformedToken))
}

/// Read a base64url-encoded string field from a compact JSON header and decode it.
///
/// # Errors
/// Returns [`JoseError::MalformedToken`] or [`JoseError::Base64Decode`] if the field is missing, malformed, or not valid base64url.
pub fn read_header_b64(header: &[u8], field: &str) -> JoseResult<Vec<u8>> {
    let val = read_header_string(header, field)?;
    crate::base64url::decode(&val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple_object() {
        let mut w = JsonWriter::new();
        w.string("alg", "HS256");
        w.number("exp", 1_300_819_380);
        w.bool("admin", true);
        let json = w.finish();
        assert_eq!(
            json,
            r#"{"alg":"HS256","exp":1300819380,"admin":true}"#
        );

        let mut r = JsonReader::new(json.as_bytes()).unwrap();
        let k1 = r.next_key().unwrap().unwrap();
        assert_eq!(k1, "alg");
        assert_eq!(r.read_string().unwrap(), "HS256");

        let k2 = r.next_key().unwrap().unwrap();
        assert_eq!(k2, "exp");
        assert_eq!(r.read_i64().unwrap(), 1_300_819_380);

        let k3 = r.next_key().unwrap().unwrap();
        assert_eq!(k3, "admin");
        assert!(r.read_bool().unwrap());

        assert!(r.next_key().unwrap().is_none());
    }

    #[test]
    fn string_escape_roundtrip() {
        let mut w = JsonWriter::new();
        w.string("msg", "line1\nline2\ttab\\slash\"quote");
        let json = w.finish();

        let mut r = JsonReader::new(json.as_bytes()).unwrap();
        r.next_key().unwrap();
        assert_eq!(r.read_string().unwrap(), "line1\nline2\ttab\\slash\"quote");
    }

    #[test]
    fn string_or_array() {
        let single = br#"{"aud":"x"}"#;
        let mut r = JsonReader::new(single).unwrap();
        r.next_key().unwrap();
        assert_eq!(r.read_string_or_string_array().unwrap(), ["x"]);

        let multi = br#"{"aud":["x","y"]}"#;
        let mut r = JsonReader::new(multi).unwrap();
        r.next_key().unwrap();
        assert_eq!(r.read_string_or_string_array().unwrap(), ["x", "y"]);
    }

    #[test]
    fn skip_nested_values() {
        let input = br#"{"a":{"nested":[1,2]},"b":"ok"}"#;
        let mut r = JsonReader::new(input).unwrap();

        let k1 = r.next_key().unwrap().unwrap();
        assert_eq!(k1, "a");
        r.skip_value().unwrap();

        let k2 = r.next_key().unwrap().unwrap();
        assert_eq!(k2, "b");
        assert_eq!(r.read_string().unwrap(), "ok");
    }

    #[test]
    fn rejects_whitespace() {
        let input = br#"{ "alg":"HS256"}"#;
        let mut r = JsonReader::new(input).unwrap();
        assert!(r.next_key().is_err());
    }

    #[test]
    fn empty_object() {
        let input = b"{}";
        let mut r = JsonReader::new(input).unwrap();
        assert!(r.next_key().unwrap().is_none());
    }

    #[test]
    fn negative_number() {
        let input = br#"{"n":-42}"#;
        let mut r = JsonReader::new(input).unwrap();
        r.next_key().unwrap();
        assert_eq!(r.read_i64().unwrap(), -42);
    }
}

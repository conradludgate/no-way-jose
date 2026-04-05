use alloc::string::String;
use alloc::vec::Vec;

use crate::JoseError;

/// Serialize a value as compact JSON bytes.
pub trait ToJson {
    /// Write this value's JSON representation into `buf`.
    fn write_json(&self, buf: &mut Vec<u8>);

    /// Convenience wrapper that allocates and returns the JSON bytes.
    fn to_json_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_json(&mut buf);
        buf
    }
}

/// Deserialize a value from compact JSON bytes.
pub trait FromJson: Sized {
    fn from_json_bytes(
        bytes: &[u8],
    ) -> Result<Self, alloc::boxed::Box<dyn core::error::Error + Send + Sync>>;
}

/// Opaque JSON payload — stores raw bytes without parsing.
pub struct RawJson(pub Vec<u8>);

impl ToJson for RawJson {
    fn write_json(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl FromJson for RawJson {
    fn from_json_bytes(
        bytes: &[u8],
    ) -> Result<Self, alloc::boxed::Box<dyn core::error::Error + Send + Sync>> {
        Ok(RawJson(bytes.to_vec()))
    }
}

// -- Writer --

/// Builds a compact JSON object incrementally.
pub struct JsonWriter {
    buf: Vec<u8>,
    first: bool,
}

impl Default for JsonWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonWriter {
    pub fn new() -> Self {
        Self {
            buf: alloc::vec![b'{'],
            first: true,
        }
    }

    fn write_key(&mut self, key: &str) {
        if !self.first {
            self.buf.push(b',');
        }
        self.first = false;
        write_escaped_string(&mut self.buf, key);
        self.buf.push(b':');
    }

    pub fn string(&mut self, key: &str, value: &str) {
        self.write_key(key);
        write_escaped_string(&mut self.buf, value);
    }

    pub fn number(&mut self, key: &str, value: i64) {
        self.write_key(key);
        let s = alloc::format!("{value}");
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn bool(&mut self, key: &str, value: bool) {
        self.write_key(key);
        self.buf
            .extend_from_slice(if value { b"true" } else { b"false" });
    }

    /// Write a single string when `values.len() == 1`, otherwise an array.
    pub fn string_or_array(&mut self, key: &str, values: &[String]) {
        self.write_key(key);
        if values.len() == 1 {
            write_escaped_string(&mut self.buf, &values[0]);
        } else {
            self.buf.push(b'[');
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    self.buf.push(b',');
                }
                write_escaped_string(&mut self.buf, v);
            }
            self.buf.push(b']');
        }
    }

    /// Write a pre-formed raw JSON value (no escaping or quoting applied).
    pub fn raw_value(&mut self, key: &str, raw_json: &[u8]) {
        self.write_key(key);
        self.buf.extend_from_slice(raw_json);
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.buf.push(b'}');
        self.buf
    }
}

/// Write a JSON object key followed by `:` into `buf`. Used by header rebuild logic.
pub(crate) fn write_json_key(buf: &mut Vec<u8>, key: &str) {
    write_escaped_string(buf, key);
    buf.push(b':');
}

fn write_escaped_string(buf: &mut Vec<u8>, s: &str) {
    buf.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            b if b < 0x20 => {
                buf.extend_from_slice(b"\\u00");
                buf.push(hex_nibble(b >> 4));
                buf.push(hex_nibble(b & 0xf));
            }
            _ => buf.push(b),
        }
    }
    buf.push(b'"');
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
    pub fn new(input: &'a [u8]) -> Result<Self, JoseError> {
        if input.first() != Some(&b'{') {
            return Err(JoseError::InvalidToken("expected JSON object"));
        }
        Ok(Self {
            input,
            pos: 1,
            first: true,
        })
    }

    /// Current byte offset into the input buffer.
    pub fn current_pos(&self) -> usize {
        self.pos
    }

    /// The raw input slice.
    pub fn input_bytes(&self) -> &'a [u8] {
        self.input
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), JoseError> {
        if self.peek() != Some(byte) {
            return Err(JoseError::InvalidToken("unexpected byte in JSON"));
        }
        self.pos += 1;
        Ok(())
    }

    /// Returns the next object key, or `None` when `}` is reached.
    /// Keys are borrowed from the input — escape sequences in keys are rejected.
    pub fn next_key(&mut self) -> Result<Option<&'a str>, JoseError> {
        if self.peek() == Some(b'}') {
            self.pos += 1;
            if self.pos != self.input.len() {
                return Err(JoseError::InvalidToken("trailing data after JSON"));
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
                None => return Err(JoseError::InvalidToken("unterminated key")),
                Some(b'"') => {
                    let key = core::str::from_utf8(&self.input[start..self.pos])
                        .map_err(|_| JoseError::InvalidToken("invalid UTF-8 in key"))?;
                    self.pos += 1;
                    self.expect(b':')?;
                    return Ok(Some(key));
                }
                Some(b'\\') => {
                    return Err(JoseError::InvalidToken("escape sequence in object key"));
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    pub fn read_string(&mut self) -> Result<String, JoseError> {
        self.expect(b'"')?;
        let mut result = String::new();
        let mut run_start = self.pos;
        loop {
            match self.input.get(self.pos) {
                None => return Err(JoseError::InvalidToken("unterminated string")),
                Some(b'"') => {
                    if run_start < self.pos {
                        let s = core::str::from_utf8(&self.input[run_start..self.pos])
                            .map_err(|_| JoseError::InvalidToken("invalid UTF-8"))?;
                        result.push_str(s);
                    }
                    self.pos += 1;
                    return Ok(result);
                }
                Some(b'\\') => {
                    if run_start < self.pos {
                        let s = core::str::from_utf8(&self.input[run_start..self.pos])
                            .map_err(|_| JoseError::InvalidToken("invalid UTF-8"))?;
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
                        _ => return Err(JoseError::InvalidToken("invalid escape sequence")),
                    }
                    run_start = self.pos;
                }
                Some(&b) if b < 0x20 => {
                    return Err(JoseError::InvalidToken("control character in string"));
                }
                Some(_) => self.pos += 1,
            }
        }
    }

    pub fn read_i64(&mut self) -> Result<i64, JoseError> {
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
            _ => return Err(JoseError::InvalidToken("expected digit")),
        }
        let s = core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| JoseError::InvalidToken("invalid number"))?;
        s.parse::<i64>()
            .map_err(|_| JoseError::InvalidToken("number out of range"))
    }

    pub fn read_bool(&mut self) -> Result<bool, JoseError> {
        if self.input.get(self.pos..self.pos + 4) == Some(b"true") {
            self.pos += 4;
            Ok(true)
        } else if self.input.get(self.pos..self.pos + 5) == Some(b"false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err(JoseError::InvalidToken("expected boolean"))
        }
    }

    /// Read a value that is either a single JSON string or an array of strings.
    pub fn read_string_or_string_array(&mut self) -> Result<Vec<String>, JoseError> {
        match self.peek() {
            Some(b'"') => {
                let s = self.read_string()?;
                Ok(alloc::vec![s])
            }
            Some(b'[') => self.read_string_array(),
            _ => Err(JoseError::InvalidToken("expected string or array")),
        }
    }

    pub fn read_string_array(&mut self) -> Result<Vec<String>, JoseError> {
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
                _ => return Err(JoseError::InvalidToken("expected ',' or ']'")),
            }
        }
    }

    /// Skip one JSON value of any type (string, number, bool, null, object, array).
    pub fn skip_value(&mut self) -> Result<(), JoseError> {
        match self.peek() {
            Some(b'"') => {
                self.skip_string()?;
            }
            Some(b'{') | Some(b'[') => self.skip_nested()?,
            Some(b't') => {
                if self.input.get(self.pos..self.pos + 4) != Some(b"true") {
                    return Err(JoseError::InvalidToken("invalid JSON value"));
                }
                self.pos += 4;
            }
            Some(b'f') => {
                if self.input.get(self.pos..self.pos + 5) != Some(b"false") {
                    return Err(JoseError::InvalidToken("invalid JSON value"));
                }
                self.pos += 5;
            }
            Some(b'n') => {
                if self.input.get(self.pos..self.pos + 4) != Some(b"null") {
                    return Err(JoseError::InvalidToken("invalid JSON value"));
                }
                self.pos += 4;
            }
            Some(b'-') | Some(b'0'..=b'9') => self.skip_number()?,
            _ => return Err(JoseError::InvalidToken("invalid JSON value")),
        }
        Ok(())
    }

    fn skip_string(&mut self) -> Result<(), JoseError> {
        self.pos += 1; // opening quote
        loop {
            match self.input.get(self.pos) {
                None => return Err(JoseError::InvalidToken("unterminated string")),
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

    fn skip_nested(&mut self) -> Result<(), JoseError> {
        let mut depth = 0u32;
        loop {
            match self.input.get(self.pos) {
                None => return Err(JoseError::InvalidToken("unterminated JSON")),
                Some(b'"') => {
                    self.skip_string()?;
                }
                Some(b'{') | Some(b'[') => {
                    depth += 1;
                    self.pos += 1;
                }
                Some(b'}') | Some(b']') => {
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

    fn skip_number(&mut self) -> Result<(), JoseError> {
        if self.input.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        if !matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
            return Err(JoseError::InvalidToken("expected digit"));
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
        if matches!(self.input.get(self.pos), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.input.get(self.pos), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.input.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(())
    }

    fn read_unicode_escape(&mut self) -> Result<char, JoseError> {
        let high = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            if self.input.get(self.pos..self.pos + 2) != Some(b"\\u") {
                return Err(JoseError::InvalidToken("expected surrogate pair"));
            }
            self.pos += 2;
            let low = self.read_hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(JoseError::InvalidToken("invalid low surrogate"));
            }
            let cp = 0x10000 + ((high as u32 - 0xD800) << 10) + (low as u32 - 0xDC00);
            char::from_u32(cp).ok_or(JoseError::InvalidToken("invalid code point"))
        } else if (0xDC00..=0xDFFF).contains(&high) {
            Err(JoseError::InvalidToken("unexpected low surrogate"))
        } else {
            char::from_u32(high as u32).ok_or(JoseError::InvalidToken("invalid code point"))
        }
    }

    fn read_hex4(&mut self) -> Result<u16, JoseError> {
        if self.pos + 4 > self.input.len() {
            return Err(JoseError::InvalidToken("incomplete unicode escape"));
        }
        let mut value = 0u16;
        for i in 0..4 {
            let digit = self.input[self.pos + i];
            let n = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(JoseError::InvalidToken("invalid hex digit")),
            };
            value = value * 16 + n as u16;
        }
        self.pos += 4;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple_object() {
        let mut w = JsonWriter::new();
        w.string("alg", "HS256");
        w.number("exp", 1300819380);
        w.bool("admin", true);
        let bytes = w.finish();
        assert_eq!(
            core::str::from_utf8(&bytes).unwrap(),
            r#"{"alg":"HS256","exp":1300819380,"admin":true}"#
        );

        let mut r = JsonReader::new(&bytes).unwrap();
        let k1 = r.next_key().unwrap().unwrap();
        assert_eq!(k1, "alg");
        assert_eq!(r.read_string().unwrap(), "HS256");

        let k2 = r.next_key().unwrap().unwrap();
        assert_eq!(k2, "exp");
        assert_eq!(r.read_i64().unwrap(), 1300819380);

        let k3 = r.next_key().unwrap().unwrap();
        assert_eq!(k3, "admin");
        assert!(r.read_bool().unwrap());

        assert!(r.next_key().unwrap().is_none());
    }

    #[test]
    fn string_escape_roundtrip() {
        let mut w = JsonWriter::new();
        w.string("msg", "line1\nline2\ttab\\slash\"quote");
        let bytes = w.finish();

        let mut r = JsonReader::new(&bytes).unwrap();
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

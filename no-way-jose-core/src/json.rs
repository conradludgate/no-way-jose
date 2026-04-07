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

const QU: u8 = b'"';
const BS: u8 = b'\\';
const BB: u8 = b'b';
const TT: u8 = b't';
const NN: u8 = b'n';
const FF: u8 = b'f';
const RR: u8 = b'r';
const UU: u8 = b'u';
const __: u8 = 0;

#[rustfmt::skip]
static ESCAPE: [u8; 256] = [
    //   0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    UU, UU, UU, UU, UU, UU, UU, UU, BB, TT, NN, UU, FF, RR, UU, UU, // 0
    UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, UU, // 1
    __, __, QU, __, __, __, __, __, __, __, __, __, __, __, __, __, // 2
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 3
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 4
    __, __, __, __, __, __, __, __, __, __, __, __, BS, __, __, __, // 5
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 6
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 7
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 8
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // 9
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // A
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // B
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // C
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // D
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // E
    __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, __, // F
];

static HEX: [u8; 16] = *b"0123456789abcdef";

fn write_escaped_string(buf: &mut String, s: &str) {
    buf.push('"');
    let mut bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (run, rest) = bytes.split_at(i);
        let (&b, rest) = rest.split_first().unwrap();

        let escape = ESCAPE[b as usize];
        i += 1;
        if escape == 0 {
            continue;
        }

        bytes = rest;
        i = 0;

        // SAFETY: we only split at ASCII bytes, which are valid UTF-8 char boundaries
        let run = unsafe { core::str::from_utf8_unchecked(run) };
        if !run.is_empty() {
            buf.push_str(run);
        }

        if escape == UU {
            cold();
            let esc = [
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[(b >> 4) as usize],
                HEX[(b & 0xf) as usize],
            ];
            // SAFETY: all bytes are ASCII
            buf.push_str(unsafe { core::str::from_utf8_unchecked(&esc) });
        } else {
            let esc = [b'\\', escape];
            // SAFETY: all bytes are ASCII
            buf.push_str(unsafe { core::str::from_utf8_unchecked(&esc) });
        }
    }

    // SAFETY: remaining bytes are valid UTF-8 — same invariant as above
    let run = unsafe { core::str::from_utf8_unchecked(bytes) };
    if !run.is_empty() {
        buf.push_str(run);
    }
    buf.push('"');
}

// -- Reader --

/// Scans a compact JSON object, yielding key-value entries for field extraction.
///
/// Expects strictly compact JSON — no whitespace between tokens.
pub struct JsonReader<'a> {
    input: &'a [u8],
    first: bool,
}

impl<'a> JsonReader<'a> {
    /// # Errors
    /// Returns [`JsonError::ExpectedObject`] if the input does not start with `{`.
    pub fn new(input: &'a [u8]) -> Result<Self, JsonError> {
        let Some((b'{', rest)) = input.split_first() else {
            return Err(JsonError::ExpectedObject);
        };
        Ok(Self {
            input: rest,
            first: true,
        })
    }

    /// The remaining unparsed input.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.input
    }

    fn peek(&self) -> Option<u8> {
        self.input.first().copied()
    }

    #[inline]
    fn expect(&mut self, byte: u8) -> Result<(), JsonError> {
        if self.peek() != Some(byte) {
            cold();
            return Err(JsonError::UnexpectedByte);
        }
        self.input = &self.input[1..];
        Ok(())
    }

    /// Returns the next object key, or `None` when `}` is reached.
    /// Keys are borrowed from the input — escape sequences in keys are rejected.
    ///
    /// # Errors
    /// Returns [`JsonError`] on malformed JSON, trailing data, or invalid UTF-8.
    pub fn next_key(&mut self) -> Result<Option<&'a str>, JsonError> {
        if self.peek() == Some(b'}') {
            self.input = &self.input[1..];
            if !self.input.is_empty() {
                return Err(JsonError::TrailingData);
            }
            return Ok(None);
        }
        if !self.first {
            self.expect(b',')?;
        }
        self.first = false;
        self.expect(b'"')?;
        let key_start = self.input;
        loop {
            let Some((&b, rest)) = self.input.split_first() else {
                return Err(JsonError::UnterminatedJson);
            };
            match b {
                b'"' => {
                    let key_len = key_start.len() - self.input.len();
                    let key = core::str::from_utf8(&key_start[..key_len])
                        .map_err(|_| JsonError::InvalidKey)?;
                    self.input = rest;
                    self.expect(b':')?;
                    return Ok(Some(key));
                }
                b'\\' => return Err(JsonError::InvalidKey),
                _ => self.input = rest,
            }
        }
    }

    /// # Errors
    /// Returns [`JsonError`] on malformed JSON, invalid escapes, or invalid UTF-8.
    pub fn read_string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"')?;
        let mut result = String::new();
        let mut bytes = self.input;
        let mut run = bytes;
        loop {
            let Some((&b, rest)) = bytes.split_first() else {
                cold();
                return Err(JsonError::InvalidString);
            };

            match b {
                b'"' | b'\\' => {
                    let run_len = bytes.as_ptr() as usize - run.as_ptr() as usize;
                    let s = core::str::from_utf8(&run[..run_len])
                        .map_err(|_| JsonError::InvalidString)?;
                    result.push_str(s);

                    if b == b'"' {
                        self.input = rest;
                        return Ok(result);
                    }

                    let Some((&esc, rest)) = rest.split_first() else {
                        cold();
                        return Err(JsonError::InvalidEscape);
                    };

                    let ch = match esc {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'b' => '\u{08}',
                        b'f' => '\u{0C}',
                        b'u' => {
                            cold();
                            self.input = rest;
                            let ch = self.read_unicode_escape()?;
                            bytes = self.input;
                            run = bytes;
                            result.push(ch);
                            continue;
                        }
                        _ => {
                            cold();
                            return Err(JsonError::InvalidEscape);
                        }
                    };

                    result.push(ch);
                    bytes = rest;
                    run = bytes;
                }
                b if b < 0x20 => {
                    cold();
                    return Err(JsonError::InvalidString);
                }
                _ => bytes = rest,
            }
        }
    }

    /// # Errors
    /// Returns [`JsonError`] if the value is not a valid JSON integer in range.
    pub fn read_i64(&mut self) -> Result<i64, JsonError> {
        let start = self.input;
        if self.input.first() == Some(&b'-') {
            self.input = &self.input[1..];
        }
        match self.input.first() {
            Some(b'0') => {
                self.input = &self.input[1..];
            }
            Some(b'1'..=b'9') => {
                self.input = &self.input[1..];
                while matches!(self.input.first(), Some(b'0'..=b'9')) {
                    self.input = &self.input[1..];
                }
            }
            _ => return Err(JsonError::InvalidNumber),
        }
        let num_len = start.len() - self.input.len();
        let s = core::str::from_utf8(&start[..num_len]).map_err(|_| JsonError::InvalidNumber)?;
        s.parse::<i64>().map_err(|_| JsonError::NumberOutOfRange)
    }

    /// # Errors
    /// Returns [`JsonError::ExpectedBoolean`] if the value is not `true` or `false`.
    pub fn read_bool(&mut self) -> Result<bool, JsonError> {
        if self.input.starts_with(b"true") {
            self.input = &self.input[4..];
            Ok(true)
        } else if self.input.starts_with(b"false") {
            self.input = &self.input[5..];
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
            self.input = &self.input[1..];
            return Ok(result);
        }
        loop {
            result.push(self.read_string()?);
            let Some((&b, rest)) = self.input.split_first() else {
                return Err(JsonError::InvalidArraySyntax);
            };
            self.input = rest;
            match b {
                b',' => {}
                b']' => return Ok(result),
                _ => return Err(JsonError::InvalidArraySyntax),
            }
        }
    }

    /// Iterate over the raw bytes of each element in a JSON array.
    ///
    /// Calls `f` with the raw `&[u8]` bytes of each element (without parsing them).
    ///
    /// # Errors
    /// Returns [`JsonError`] on malformed array syntax.
    pub fn read_raw_array(
        &mut self,
        mut f: impl FnMut(&'a [u8]) -> Result<(), JsonError>,
    ) -> Result<(), JsonError> {
        self.expect(b'[')?;
        if self.peek() == Some(b']') {
            self.input = &self.input[1..];
            return Ok(());
        }
        loop {
            let before = self.input;
            self.skip_value()?;
            let consumed = before.len() - self.input.len();
            f(&before[..consumed])?;
            let Some((&b, rest)) = self.input.split_first() else {
                return Err(JsonError::InvalidArraySyntax);
            };
            self.input = rest;
            match b {
                b',' => {}
                b']' => return Ok(()),
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
            Some(b'"') => self.skip_string(),
            Some(b'{' | b'[') => self.skip_nested(),
            Some(b't') => {
                if !self.input.starts_with(b"true") {
                    return Err(JsonError::InvalidValue);
                }
                self.input = &self.input[4..];
                Ok(())
            }
            Some(b'f') => {
                if !self.input.starts_with(b"false") {
                    return Err(JsonError::InvalidValue);
                }
                self.input = &self.input[5..];
                Ok(())
            }
            Some(b'n') => {
                if !self.input.starts_with(b"null") {
                    return Err(JsonError::InvalidValue);
                }
                self.input = &self.input[4..];
                Ok(())
            }
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => Err(JsonError::InvalidValue),
        }
    }

    fn skip_string(&mut self) -> Result<(), JsonError> {
        self.input = &self.input[1..]; // opening quote
        loop {
            let Some((&b, rest)) = self.input.split_first() else {
                return Err(JsonError::InvalidString);
            };
            self.input = rest;
            match b {
                b'"' => return Ok(()),
                b'\\' => {
                    let Some((_, rest)) = self.input.split_first() else {
                        return Err(JsonError::InvalidString);
                    };
                    self.input = rest;
                }
                _ => {}
            }
        }
    }

    fn skip_nested(&mut self) -> Result<(), JsonError> {
        let mut depth = 0u32;
        loop {
            let Some((&b, rest)) = self.input.split_first() else {
                return Err(JsonError::UnterminatedJson);
            };
            match b {
                b'"' => self.skip_string()?,
                b'{' | b'[' => {
                    depth += 1;
                    self.input = rest;
                }
                b'}' | b']' => {
                    depth -= 1;
                    self.input = rest;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                _ => self.input = rest,
            }
        }
    }

    fn skip_number(&mut self) -> Result<(), JsonError> {
        if self.input.first() == Some(&b'-') {
            self.input = &self.input[1..];
        }
        match self.input.first() {
            Some(b'0') => {
                self.input = &self.input[1..];
            }
            Some(b'1'..=b'9') => {
                self.input = &self.input[1..];
                while matches!(self.input.first(), Some(b'0'..=b'9')) {
                    self.input = &self.input[1..];
                }
            }
            _ => return Err(JsonError::InvalidNumber),
        }
        if self.input.first() == Some(&b'.') {
            self.input = &self.input[1..];
            while matches!(self.input.first(), Some(b'0'..=b'9')) {
                self.input = &self.input[1..];
            }
        }
        if matches!(self.input.first(), Some(b'e' | b'E')) {
            self.input = &self.input[1..];
            if matches!(self.input.first(), Some(b'+' | b'-')) {
                self.input = &self.input[1..];
            }
            while matches!(self.input.first(), Some(b'0'..=b'9')) {
                self.input = &self.input[1..];
            }
        }
        Ok(())
    }

    fn read_unicode_escape(&mut self) -> Result<char, JsonError> {
        let high = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            if !self.input.starts_with(b"\\u") {
                return Err(JsonError::InvalidUnicodeEscape);
            }
            self.input = &self.input[2..];
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
        let Some(hex) = self.input.get(..4) else {
            return Err(JsonError::InvalidUnicodeEscape);
        };
        let mut value = 0u16;
        for &digit in hex {
            let n = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(JsonError::InvalidUnicodeEscape),
            };
            value = value * 16 + u16::from(n);
        }
        self.input = &self.input[4..];
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

#[cold]
#[inline(always)]
fn cold() {}

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
        assert_eq!(json, r#"{"alg":"HS256","exp":1300819380,"admin":true}"#);

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
    fn multibyte_utf8_preserved() {
        let cases: &[(&str, &str)] = &[
            // 2-byte, 3-byte, 4-byte sequences
            ("café ☕ 𝕳ello", r#""café ☕ 𝕳ello""#),
            // multi-byte adjacent to escape sequences
            ("é\nü", r#""é\nü""#),
            ("\tà", r#""\tà""#),
            ("ñ\"ñ", r#""ñ\"ñ""#),
            // entirely non-ASCII
            ("日本語", r#""日本語""#),
            // multi-byte at boundaries
            ("ö", r#""ö""#),
            // control char between multi-byte
            ("á\x01ß", r#""á\u0001ß""#),
        ];
        for &(input, expected_value) in cases {
            let mut w = JsonWriter::new();
            w.string("v", input);
            let json = w.finish();
            assert_eq!(
                json,
                alloc::format!(r#"{{"v":{expected_value}}}"#),
                "failed for input: {input:?}"
            );

            let mut r = JsonReader::new(json.as_bytes()).unwrap();
            r.next_key().unwrap();
            assert_eq!(
                r.read_string().unwrap(),
                input,
                "roundtrip failed for input: {input:?}"
            );
        }
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

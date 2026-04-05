use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::JoseError;

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// # Errors
/// Returns [`crate::JoseError::Base64DecodeError`] if the input is not valid base64url.
pub fn decode(s: &str) -> Result<Vec<u8>, JoseError> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| JoseError::Base64DecodeError)
}

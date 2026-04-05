use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use error_stack::ResultExt;

use crate::JoseResult;
use crate::error::JoseError;

#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// # Errors
/// Returns [`JoseError::Base64Decode`] if the input is not valid base64url.
pub fn decode(s: &str) -> JoseResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(s).change_context(JoseError::Base64Decode)
}

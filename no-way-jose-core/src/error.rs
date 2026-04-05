use core::error::Error;
use core::fmt;

use error_stack::Report;

/// Convenience alias for results carrying a `Report<JoseError>`.
pub type JoseResult<T> = Result<T, Report<JoseError>>;

/// Top-level error context for all JOSE operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum JoseError {
    Base64Decode,
    MalformedToken,
    AlgorithmMismatch,
    HeaderValidation(HeaderError),
    InvalidKey,
    CryptoError,
    ClaimsValidation(ClaimsError),
    PayloadError,
}

impl fmt::Display for JoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base64Decode => f.write_str("base64url decoding failed"),
            Self::MalformedToken => f.write_str("malformed token"),
            Self::AlgorithmMismatch => f.write_str("algorithm mismatch"),
            Self::HeaderValidation(h) => write!(f, "header validation failed: {h}"),
            Self::InvalidKey => f.write_str("invalid key"),
            Self::CryptoError => f.write_str("cryptographic operation failed"),
            Self::ClaimsValidation(c) => write!(f, "claims validation failed: {c}"),
            Self::PayloadError => f.write_str("payload encoding error"),
        }
    }
}

impl Error for JoseError {}

/// Header validation errors.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HeaderError {
    TypMismatch,
    CtyMismatch,
    UnsupportedCritExtension,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypMismatch => f.write_str("typ mismatch"),
            Self::CtyMismatch => f.write_str("cty mismatch"),
            Self::UnsupportedCritExtension => f.write_str("unsupported crit extension"),
        }
    }
}

impl Error for HeaderError {}

/// Claims validation errors.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ClaimsError {
    MissingExpiry,
    Expired,
    NotYetValid,
    IssuerMismatch,
    AudienceMismatch,
}

impl fmt::Display for ClaimsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingExpiry => f.write_str("missing exp claim"),
            Self::Expired => f.write_str("token expired"),
            Self::NotYetValid => f.write_str("token not yet valid"),
            Self::IssuerMismatch => f.write_str("issuer mismatch"),
            Self::AudienceMismatch => f.write_str("audience mismatch"),
        }
    }
}

impl Error for ClaimsError {}

/// JSON parsing errors from [`crate::json::JsonReader`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum JsonError {
    ExpectedObject,
    UnexpectedByte,
    TrailingData,
    InvalidKey,
    InvalidString,
    InvalidEscape,
    InvalidNumber,
    NumberOutOfRange,
    ExpectedBoolean,
    ExpectedStringOrArray,
    InvalidArraySyntax,
    InvalidValue,
    UnterminatedJson,
    InvalidUnicodeEscape,
    MissingField,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExpectedObject => f.write_str("expected JSON object"),
            Self::UnexpectedByte => f.write_str("unexpected byte in JSON"),
            Self::TrailingData => f.write_str("trailing data after JSON"),
            Self::InvalidKey => f.write_str("invalid object key"),
            Self::InvalidString => f.write_str("invalid string"),
            Self::InvalidEscape => f.write_str("invalid escape sequence"),
            Self::InvalidNumber => f.write_str("invalid number"),
            Self::NumberOutOfRange => f.write_str("number out of range"),
            Self::ExpectedBoolean => f.write_str("expected boolean"),
            Self::ExpectedStringOrArray => f.write_str("expected string or array"),
            Self::InvalidArraySyntax => f.write_str("invalid array syntax"),
            Self::InvalidValue => f.write_str("invalid JSON value"),
            Self::UnterminatedJson => f.write_str("unterminated JSON"),
            Self::InvalidUnicodeEscape => f.write_str("invalid unicode escape"),
            Self::MissingField => f.write_str("missing required field"),
        }
    }
}

impl Error for JsonError {}

/// Token compact-serialization format errors.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TokenFormatError {
    MissingHeader,
    MissingPayload,
    MissingSignature,
    MissingEncryptedKey,
    MissingIv,
    MissingCiphertext,
    MissingTag,
    MissingAlg,
    MissingEnc,
    MalformedHeaderJson,
}

impl fmt::Display for TokenFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader => f.write_str("missing header"),
            Self::MissingPayload => f.write_str("missing payload"),
            Self::MissingSignature => f.write_str("missing signature"),
            Self::MissingEncryptedKey => f.write_str("missing encrypted key"),
            Self::MissingIv => f.write_str("missing IV"),
            Self::MissingCiphertext => f.write_str("missing ciphertext"),
            Self::MissingTag => f.write_str("missing tag"),
            Self::MissingAlg => f.write_str("missing alg in header"),
            Self::MissingEnc => f.write_str("missing enc in header"),
            Self::MalformedHeaderJson => f.write_str("malformed header JSON"),
        }
    }
}

impl Error for TokenFormatError {}

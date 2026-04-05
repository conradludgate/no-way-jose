use alloc::string::String;
use alloc::vec::Vec;

use crate::__private::Sealed;
use crate::JoseError;
use crate::key::{Decrypting, Encrypting, HasKey, KeyInner};

/// Marker trait for JWE key management algorithm identifiers (RFC 7518 §4).
pub trait JweKeyManagement: Sealed + Send + Sync + Sized + 'static {
    const ALG: &'static str;
}

/// Marker trait for JWE content encryption algorithm identifiers (RFC 7518 §5).
pub trait JweContentEncryption: Sealed + Send + Sync + Sized + 'static {
    const ENC: &'static str;
    const KEY_LEN: usize;
    const IV_LEN: usize;
    const TAG_LEN: usize;
}

/// Output of key encryption: the wrapped CEK and any extra JWE header parameters
/// produced by the key management algorithm.
pub struct KeyEncryptionResult {
    pub encrypted_key: Vec<u8>,
    pub cek: Vec<u8>,
    /// Extra header parameters as `(key, raw_json_value)` pairs.
    /// Algorithms like AES-GCM-KW, ECDH-ES, and PBES2 use this to inject
    /// `iv`/`tag`, `epk`/`apu`/`apv`, or `p2s`/`p2c` into the JWE header.
    pub extra_headers: Vec<(String, Vec<u8>)>,
}

/// Encrypt/wrap a Content Encryption Key using a key management algorithm.
pub trait KeyEncryptor: JweKeyManagement + HasKey<Encrypting> {
    fn encrypt_cek(
        key: &KeyInner<Self, Encrypting>,
        cek_len: usize,
    ) -> Result<KeyEncryptionResult, JoseError>;
}

/// Decrypt/unwrap a Content Encryption Key using a key management algorithm.
pub trait KeyDecryptor: JweKeyManagement + HasKey<Decrypting> {
    /// Recover the CEK from the `encrypted_key` field of a JWE token.
    ///
    /// `header` contains the raw JSON header bytes for algorithms that need
    /// to extract additional parameters (e.g. `iv`/`tag` for AES-GCM-KW).
    ///
    /// `cek_len` is the expected CEK length from the content encryption algorithm.
    /// Algorithms like ECDH-ES direct agreement need this to derive the correct key size.
    fn decrypt_cek(
        key: &KeyInner<Self, Decrypting>,
        encrypted_key: &[u8],
        header: &[u8],
        cek_len: usize,
    ) -> Result<Vec<u8>, JoseError>;
}

/// Encrypt plaintext using a content encryption algorithm.
/// The implementation generates the IV internally.
pub trait ContentEncryptor: JweContentEncryption {
    fn encrypt(cek: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<EncryptionOutput, JoseError>;
}

/// Decrypt ciphertext using a content encryption algorithm.
pub trait ContentDecryptor: JweContentEncryption {
    /// Decrypt and authenticate the ciphertext using the CEK, IV, AAD, and tag.
    fn decrypt(
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, JoseError>;
}

/// Output of content encryption: IV, ciphertext, and authentication tag.
pub struct EncryptionOutput {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

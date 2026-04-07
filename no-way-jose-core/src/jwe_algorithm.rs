use alloc::string::String;
use alloc::vec::Vec;

use crate::JoseResult;
use crate::key::{Encrypting, HasKey, KeyInner};

/// Marker trait for JWE key management algorithm identifiers (RFC 7518 §4).
pub trait JweKeyManagement: Send + Sync + Sized + 'static {
    const ALG: &'static str;
}

/// Marker trait for JWE content encryption algorithm identifiers (RFC 7518 §5).
pub trait JweContentEncryption: Send + Sync + Sized + 'static {
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
    pub extra_headers: Vec<(String, String)>,
}

/// JWE key management: encrypt/wrap and decrypt/unwrap the Content Encryption Key.
///
/// For symmetric algorithms (dir, AES-KW, AES-GCM-KW, PBES2), the key type is the
/// shared secret. For asymmetric algorithms (RSA, ECDH-ES), the key type is the
/// private key — `encrypt_cek` derives the public component internally.
pub trait KeyManager: JweKeyManagement + HasKey<Encrypting> {
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] or [`crate::JoseError::InvalidKey`] if key encryption fails.
    fn encrypt_cek(
        key: &KeyInner<Self, Encrypting>,
        cek_len: usize,
    ) -> JoseResult<KeyEncryptionResult>;

    /// Recover the CEK from the `encrypted_key` field of a JWE token.
    ///
    /// `header` contains the raw JSON header bytes for algorithms that need
    /// to extract additional parameters (e.g. `iv`/`tag` for AES-GCM-KW).
    ///
    /// `cek_len` is the expected CEK length from the content encryption algorithm.
    /// Algorithms like ECDH-ES direct agreement need this to derive the correct key size.
    ///
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] or [`crate::JoseError::InvalidKey`] if decryption fails.
    fn decrypt_cek(
        key: &KeyInner<Self, Encrypting>,
        encrypted_key: &[u8],
        header: &[u8],
        cek_len: usize,
    ) -> JoseResult<Vec<u8>>;
}

/// Encrypt plaintext using a content encryption algorithm.
/// The implementation generates the IV internally.
pub trait ContentEncryptor: JweContentEncryption {
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] if encryption fails.
    fn encrypt(cek: &[u8], aad: &[u8], plaintext: &[u8]) -> JoseResult<EncryptionOutput>;
}

/// Decrypt ciphertext using a content encryption algorithm.
pub trait ContentDecryptor: JweContentEncryption {
    /// Decrypt and authenticate the ciphertext using the CEK, IV, AAD, and tag.
    ///
    /// # Errors
    /// Returns [`crate::JoseError::CryptoError`] if decryption or authentication fails.
    fn decrypt(
        cek: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> JoseResult<Vec<u8>>;
}

/// Output of content encryption: IV, ciphertext, and authentication tag.
pub struct EncryptionOutput {
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

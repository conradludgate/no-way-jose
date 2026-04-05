use alloc::vec::Vec;

use error_stack::Report;

use crate::__private::Sealed;
use crate::JoseResult;
use crate::error::JoseError;
use crate::jwe_algorithm::{JweKeyManagement, KeyDecryptor, KeyEncryptionResult, KeyEncryptor};
use crate::key::{Decrypting, Encrypting, HasKey, Key};

/// Direct key agreement — the shared symmetric key IS the CEK.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dir;

impl Sealed for Dir {}

impl JweKeyManagement for Dir {
    const ALG: &'static str = "dir";
}

impl HasKey<Encrypting> for Dir {
    type Key = Vec<u8>;
}

impl HasKey<Decrypting> for Dir {
    type Key = Vec<u8>;
}

/// Non-empty `encrypted_key` in direct key agreement.
#[derive(Debug, Clone)]
pub struct NonEmptyEncryptedKey;

impl core::fmt::Display for NonEmptyEncryptedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("dir: encrypted_key must be empty")
    }
}

impl core::error::Error for NonEmptyEncryptedKey {}

impl KeyEncryptor for Dir {
    fn encrypt_cek(key: &Vec<u8>, cek_len: usize) -> JoseResult<KeyEncryptionResult> {
        if key.len() != cek_len {
            return Err(Report::new(JoseError::InvalidKey));
        }
        Ok(KeyEncryptionResult {
            encrypted_key: Vec::new(),
            cek: key.clone(),
            extra_headers: Vec::new(),
        })
    }
}

impl KeyDecryptor for Dir {
    fn decrypt_cek(
        key: &Vec<u8>,
        encrypted_key: &[u8],
        _header: &[u8],
        _cek_len: usize,
    ) -> JoseResult<Vec<u8>> {
        if !encrypted_key.is_empty() {
            return Err(Report::new(NonEmptyEncryptedKey).change_context(JoseError::MalformedToken));
        }
        Ok(key.clone())
    }
}

/// Wrap raw key bytes as a `dir` encryption key.
///
/// The key length must match the content encryption algorithm's key size
/// (e.g. 32 bytes for A256GCM). A length mismatch is detected at encrypt time.
#[must_use]
pub fn encryption_key(raw: Vec<u8>) -> Key<Dir, Encrypting> {
    Key::new(raw)
}

/// Wrap raw key bytes as a `dir` decryption key.
#[must_use]
pub fn decryption_key(raw: Vec<u8>) -> Key<Dir, Decrypting> {
    Key::new(raw)
}

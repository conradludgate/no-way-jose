use alloc::vec::Vec;

use crate::__private::Sealed;
use crate::JoseError;
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

impl KeyEncryptor for Dir {
    fn encrypt_cek(key: &Vec<u8>, cek_len: usize) -> Result<KeyEncryptionResult, JoseError> {
        if key.len() != cek_len {
            return Err(JoseError::InvalidKey);
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
    ) -> Result<Vec<u8>, JoseError> {
        if !encrypted_key.is_empty() {
            return Err(JoseError::InvalidToken("dir: encrypted_key must be empty"));
        }
        Ok(key.clone())
    }
}

/// Wrap raw key bytes as a `dir` encryption key.
///
/// The key length must match the content encryption algorithm's key size
/// (e.g. 32 bytes for A256GCM). A length mismatch is detected at encrypt time.
pub fn encryption_key(raw: Vec<u8>) -> Key<Dir, Encrypting> {
    Key::new(raw)
}

/// Wrap raw key bytes as a `dir` decryption key.
pub fn decryption_key(raw: Vec<u8>) -> Key<Dir, Decrypting> {
    Key::new(raw)
}

use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::__private::Sealed;
use crate::algorithm::JwsAlgorithm;
use crate::jwe_algorithm::{JweContentEncryption, JweKeyManagement};

/// Distinguishes JWS (signed) from JWE (encrypted) at the type level.
/// Each purpose carries its own wire-format data shape.
pub trait Purpose: Sealed {
    type SealedData;
}

/// Marks a token as signed with JWS algorithm `A`.
pub struct Signed<A: JwsAlgorithm>(PhantomData<A>);

impl<A: JwsAlgorithm> Sealed for Signed<A> {}
impl<A: JwsAlgorithm> Purpose for Signed<A> {
    type SealedData = SignedData;
}

/// Marks a token as encrypted with key management algorithm `KM` and
/// content encryption algorithm `CE`.
pub struct Encrypted<KM: JweKeyManagement, CE: JweContentEncryption>(PhantomData<(KM, CE)>);

impl<KM: JweKeyManagement, CE: JweContentEncryption> Sealed for Encrypted<KM, CE> {}
impl<KM: JweKeyManagement, CE: JweContentEncryption> Purpose for Encrypted<KM, CE> {
    type SealedData = EncryptedData;
}

/// Wire-format data for a JWS compact token.
pub struct SignedData {
    pub(crate) payload_b64: String,
    pub(crate) signature: Vec<u8>,
}

/// Wire-format data for a JWE compact token (`encrypted_key`, iv, ciphertext, tag).
pub struct EncryptedData {
    pub(crate) encrypted_key: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Vec<u8>,
}

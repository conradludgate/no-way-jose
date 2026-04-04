use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::algorithm::JwsAlgorithm;
use crate::sealed::Sealed;

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

/// Wire-format data for a JWS compact token.
pub struct SignedData {
    pub(crate) payload_b64: String,
    pub(crate) signature: Vec<u8>,
}

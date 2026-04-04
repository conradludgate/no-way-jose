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

/// Wire-format data for a JWS compact token (payload + signature).
pub struct SignedData {
    pub(crate) payload: alloc::boxed::Box<[u8]>,
    pub(crate) signature: alloc::vec::Vec<u8>,
}

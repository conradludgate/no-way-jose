use core::marker::PhantomData;

use crate::__private::Sealed;
use crate::algorithm::JwsAlgorithm;
use crate::jwe_algorithm::{JweContentEncryption, JweKeyManagement};

/// Distinguishes JWS (signed) from JWE (encrypted) at the type level.
pub trait Purpose: Sealed {}

/// Marks a token as signed with JWS algorithm `A`.
pub struct Signed<A: JwsAlgorithm>(PhantomData<A>);

impl<A: JwsAlgorithm> Sealed for Signed<A> {}
impl<A: JwsAlgorithm> Purpose for Signed<A> {}

/// Marks a token as encrypted with key management algorithm `KM` and
/// content encryption algorithm `CE`.
pub struct Encrypted<KM: JweKeyManagement, CE: JweContentEncryption>(PhantomData<(KM, CE)>);

impl<KM: JweKeyManagement, CE: JweContentEncryption> Sealed for Encrypted<KM, CE> {}
impl<KM: JweKeyManagement, CE: JweContentEncryption> Purpose for Encrypted<KM, CE> {}

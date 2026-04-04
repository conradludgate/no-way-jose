use crate::sealed::Sealed;

pub type KeyInner<A, K> = <A as HasKey<K>>::Key;

/// Generic key type, parameterized by algorithm and purpose.
pub struct Key<A: HasKey<K>, K: KeyPurpose>(pub KeyInner<A, K>);

impl<A: HasKey<K>, K: KeyPurpose> Clone for Key<A, K>
where
    KeyInner<A, K>: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Declares that an algorithm supports a given key purpose,
/// mapping to a concrete inner key type.
pub trait HasKey<K: KeyPurpose>: Sized + 'static {
    type Key;
}

/// Marker for key purpose.
pub trait KeyPurpose: Sealed + Send + Sync + Sized + 'static {}

/// Private key used for signing.
#[derive(Clone, Copy, Debug, Default)]
pub struct Signing;

/// Public key used for verification.
#[derive(Clone, Copy, Debug, Default)]
pub struct Verifying;

impl Sealed for Signing {}
impl Sealed for Verifying {}
impl KeyPurpose for Signing {}
impl KeyPurpose for Verifying {}

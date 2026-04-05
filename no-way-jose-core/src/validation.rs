use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::JoseError;

/// Validation rules for the claims in a JWT.
pub trait Validate {
    type Claims;

    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError>;

    fn and_then<V>(self, other: V) -> impl Validate<Claims = Self::Claims>
    where
        Self: Sized,
        V: Validate<Claims = Self::Claims>,
    {
        ValidateThen(self, other)
    }

    fn map<T>(self, f: impl for<'a> Fn(&'a T) -> &'a Self::Claims) -> impl Validate<Claims = T>
    where
        Self: Sized,
    {
        Map(PhantomData::<T>, f, self)
    }
}

/// Perform no validation. Caller accepts responsibility.
pub struct NoValidation<Claims>(PhantomData<Claims>);

impl<Claims> NoValidation<Claims> {
    pub fn dangerous_no_validation() -> Self {
        NoValidation(PhantomData)
    }
}

impl<Claims> Validate for NoValidation<Claims> {
    type Claims = Claims;
    fn validate(&self, _: &Self::Claims) -> Result<(), JoseError> {
        Ok(())
    }
}

struct Map<Claims, F, T>(PhantomData<Claims>, F, T);

impl<Claims, F, T> Validate for Map<Claims, F, T>
where
    F: for<'a> Fn(&'a Claims) -> &'a T::Claims,
    T: Validate,
{
    type Claims = Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        self.2.validate((self.1)(claims))
    }
}

struct ValidateThen<T, U>(T, U);

impl<T: Validate, U: Validate<Claims = T::Claims>> Validate for ValidateThen<T, U> {
    type Claims = T::Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        self.0.validate(claims)?;
        self.1.validate(claims)
    }
}

impl<T: Validate> Validate for Vec<T> {
    type Claims = T::Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        <[T]>::validate(self, claims)
    }
}

impl<T: Validate> Validate for [T] {
    type Claims = T::Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        for v in self {
            T::validate(v, claims)?;
        }
        Ok(())
    }
}

impl<T: Validate + ?Sized> Validate for Box<T> {
    type Claims = T::Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        T::validate(self, claims)
    }
}

impl<T: Validate + ?Sized> Validate for Arc<T> {
    type Claims = T::Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        T::validate(self, claims)
    }
}

impl<T: Validate + ?Sized> Validate for Rc<T> {
    type Claims = T::Claims;
    fn validate(&self, claims: &Self::Claims) -> Result<(), JoseError> {
        T::validate(self, claims)
    }
}

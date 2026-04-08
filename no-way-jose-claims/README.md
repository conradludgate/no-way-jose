# no-way-jose-claims

JWT registered claims and composable validators for [no-way-jose](https://github.com/conradludgate/no-way-jose).

Provides `RegisteredClaims` (RFC 7519 §4.1) with builder methods and ready-made validators: `HasExpiry`, `Time`, `FromIssuer`, and `ForAudience`. Validators implement [`Validate`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/validation/trait.Validate.html) from [no-way-jose-core](https://docs.rs/no-way-jose-core) and compose with `and_then`. Signed and encrypted tokens are represented in core by [`CompactJws`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJws.html) and [`CompactJwe`](https://docs.rs/no-way-jose-core/latest/no_way_jose_core/type.CompactJwe.html).

This is the only crate in the workspace that depends on `std`; it uses [jiff](https://docs.rs/jiff) for timestamps (`exp`, `nbf`, `iat`), which serialize as integer seconds (NumericDate) on the wire.

## Getting started

`RegisteredClaims::new` seeds `iat` and `nbf` from `now` and sets `exp` to `now + ttl`. Use the builder methods to fill issuer, subject, audience, and optional `jti`:

```rust
fn main() -> Result<(), jiff::Error> {
    use jiff::SignedDuration;
    use no_way_jose_claims::RegisteredClaims;

    let _claims = RegisteredClaims::new(jiff::Timestamp::UNIX_EPOCH, SignedDuration::from_hours(1))?
        .from_issuer("https://issuer.example")
        .for_subject("user-42")
        .for_audience("my-api")
        .with_token_id("abc123");

    Ok(())
}
```

## Custom validation

Chain rules with `and_then`. For claim structs that embed `RegisteredClaims`, reuse the same validators via `Validate::map`, which selects the nested field before running the inner rule:

```rust
fn main() -> Result<(), jiff::Error> {
    use jiff::SignedDuration;
    use no_way_jose_claims::{
        ForAudience, FromIssuer, HasExpiry, RegisteredClaims, Time, Validate,
    };

    struct AppClaims {
        registered: RegisteredClaims,
    }

    let claims = AppClaims {
        registered: RegisteredClaims::new(
            jiff::Timestamp::UNIX_EPOCH,
            SignedDuration::from_hours(1),
        )?
        .from_issuer("auth.example.com")
        .for_audience("my-api"),
    };

    let validator = HasExpiry
        .and_then(Time::valid_at(jiff::Timestamp::UNIX_EPOCH))
        .and_then(FromIssuer("auth.example.com"))
        .and_then(ForAudience("my-api"))
        .map(|c: &AppClaims| &c.registered);

    assert!(validator.validate(&claims).is_ok());

    Ok(())
}
```

A typical flat pipeline on `RegisteredClaims` alone:

```rust
fn main() -> Result<(), jiff::Error> {
    use jiff::SignedDuration;
    use no_way_jose_claims::{
        ForAudience, FromIssuer, HasExpiry, RegisteredClaims, Time, Validate,
    };

    let claims = RegisteredClaims::new(
        jiff::Timestamp::UNIX_EPOCH,
        SignedDuration::from_hours(1),
    )?
    .from_issuer("auth.example.com")
    .for_audience("my-api");

    let validator = HasExpiry
        .and_then(Time::valid_at(jiff::Timestamp::UNIX_EPOCH))
        .and_then(FromIssuer("auth.example.com"))
        .and_then(ForAudience("my-api"));

    assert!(validator.validate(&claims).is_ok());

    Ok(())
}
```

See the [workspace README](https://github.com/conradludgate/no-way-jose) for full examples.

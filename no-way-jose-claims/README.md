# no-way-jose-claims

JWT registered claims and composable validators for [no-way-jose](https://github.com/conradludgate/no-way-jose).

Provides `RegisteredClaims` (RFC 7519 §4.1) with typed fields for `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, and `jti`, plus a builder API for constructing them.

Validators compose with `and_then`:

```rust
use no_way_jose_claims::{HasExpiry, Time, FromIssuer, ForAudience};

let validator = HasExpiry
    .and_then(Time::valid_now())
    .and_then(FromIssuer("auth.example.com"))
    .and_then(ForAudience("my-api"));
```

Uses [jiff](https://docs.rs/jiff) for time handling. This is the only crate in the workspace that requires `std`.

See the [workspace README](https://github.com/conradludgate/no-way-jose) for full examples.

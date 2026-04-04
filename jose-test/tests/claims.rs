/// Claims validation tests.
use jose_core::validation::Validate;
use jose_json::jiff;
use jose_json::{ForAudience, FromIssuer, HasExpiry, RegisteredClaims, Time};

#[test]
fn has_expiry_passes_when_present() {
    let claims = RegisteredClaims {
        exp: Some(9999999999),
        ..Default::default()
    };
    assert!(HasExpiry.validate(&claims).is_ok());
}

#[test]
fn has_expiry_fails_when_missing() {
    let claims = RegisteredClaims::default();
    assert!(HasExpiry.validate(&claims).is_err());
}

#[test]
fn time_rejects_expired() {
    let past = jiff::Timestamp::from_second(1000).unwrap();
    let claims = RegisteredClaims {
        exp: Some(500),
        ..Default::default()
    };
    assert!(Time::valid_at(past).validate(&claims).is_err());
}

#[test]
fn time_accepts_valid() {
    let now = jiff::Timestamp::from_second(1000).unwrap();
    let claims = RegisteredClaims {
        exp: Some(2000),
        nbf: Some(500),
        ..Default::default()
    };
    assert!(Time::valid_at(now).validate(&claims).is_ok());
}

#[test]
fn time_rejects_not_yet_valid() {
    let early = jiff::Timestamp::from_second(100).unwrap();
    let claims = RegisteredClaims {
        nbf: Some(500),
        ..Default::default()
    };
    assert!(Time::valid_at(early).validate(&claims).is_err());
}

#[test]
fn from_issuer_validates() {
    let claims = RegisteredClaims {
        iss: Some("example.com".into()),
        ..Default::default()
    };
    assert!(FromIssuer("example.com").validate(&claims).is_ok());
    assert!(FromIssuer("other.com").validate(&claims).is_err());
}

#[test]
fn for_audience_validates() {
    let claims = RegisteredClaims {
        aud: Some("my-app".into()),
        ..Default::default()
    };
    assert!(ForAudience("my-app").validate(&claims).is_ok());
    assert!(ForAudience("other-app").validate(&claims).is_err());
}

#[test]
fn composable_validators() {
    let claims = RegisteredClaims {
        iss: Some("example.com".into()),
        aud: Some("my-app".into()),
        exp: Some(9999999999),
        nbf: Some(0),
        ..Default::default()
    };

    let now = jiff::Timestamp::from_second(1000).unwrap();
    let v = HasExpiry
        .and_then(Time::valid_at(now))
        .and_then(FromIssuer("example.com"))
        .and_then(ForAudience("my-app"));

    assert!(v.validate(&claims).is_ok());
}

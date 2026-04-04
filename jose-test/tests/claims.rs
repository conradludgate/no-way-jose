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
        aud: Some(vec!["my-app".into()]),
        ..Default::default()
    };
    assert!(ForAudience("my-app").validate(&claims).is_ok());
    assert!(ForAudience("other-app").validate(&claims).is_err());
}

#[test]
fn for_audience_validates_array() {
    let claims = RegisteredClaims {
        aud: Some(vec!["app-a".into(), "app-b".into()]),
        ..Default::default()
    };
    assert!(ForAudience("app-a").validate(&claims).is_ok());
    assert!(ForAudience("app-b").validate(&claims).is_ok());
    assert!(ForAudience("app-c").validate(&claims).is_err());
}

#[test]
fn aud_deserializes_string_and_array() {
    let single: RegisteredClaims = serde_json::from_str(r#"{"aud":"x"}"#).unwrap();
    assert_eq!(single.aud, Some(vec!["x".into()]));

    let array: RegisteredClaims = serde_json::from_str(r#"{"aud":["x","y"]}"#).unwrap();
    assert_eq!(array.aud, Some(vec!["x".into(), "y".into()]));

    let single_json = serde_json::to_string(&single).unwrap();
    assert!(single_json.contains(r#""aud":"x""#));

    let array_json = serde_json::to_string(&array).unwrap();
    assert!(array_json.contains(r#""aud":["x","y"]"#));
}

#[test]
fn composable_validators() {
    let claims = RegisteredClaims {
        iss: Some("example.com".into()),
        aud: Some(vec!["my-app".into()]),
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

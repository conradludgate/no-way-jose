/// Claims validation tests.
use no_way_jose_claims::jiff;
use no_way_jose_claims::{ForAudience, FromIssuer, HasExpiry, RegisteredClaims, Time};
use no_way_jose_core::json::{FromJson, ToJson};
use no_way_jose_core::validation::Validate;

fn ts(secs: i64) -> jiff::Timestamp {
    jiff::Timestamp::from_second(secs).unwrap()
}

#[test]
fn has_expiry_passes_when_present() {
    let claims = RegisteredClaims {
        exp: Some(ts(9999999999)),
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
    let claims = RegisteredClaims {
        exp: Some(ts(500)),
        ..Default::default()
    };
    assert!(Time::valid_at(ts(1000)).validate(&claims).is_err());
}

#[test]
fn time_accepts_valid() {
    let claims = RegisteredClaims {
        exp: Some(ts(2000)),
        nbf: Some(ts(500)),
        ..Default::default()
    };
    assert!(Time::valid_at(ts(1000)).validate(&claims).is_ok());
}

#[test]
fn time_rejects_not_yet_valid() {
    let claims = RegisteredClaims {
        nbf: Some(ts(500)),
        ..Default::default()
    };
    assert!(Time::valid_at(ts(100)).validate(&claims).is_err());
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
    let single = RegisteredClaims::from_json_bytes(br#"{"aud":"x"}"#).unwrap();
    assert_eq!(single.aud, Some(vec!["x".into()]));

    let array = RegisteredClaims::from_json_bytes(br#"{"aud":["x","y"]}"#).unwrap();
    assert_eq!(array.aud, Some(vec!["x".into(), "y".into()]));

    let single_json = single.to_json();
    assert!(single_json.contains(r#""aud":"x""#));

    let array_json = array.to_json();
    assert!(array_json.contains(r#""aud":["x","y"]"#));
}

#[test]
fn composable_validators() {
    let claims = RegisteredClaims {
        iss: Some("example.com".into()),
        aud: Some(vec!["my-app".into()]),
        exp: Some(ts(9999999999)),
        nbf: Some(ts(0)),
        ..Default::default()
    };

    let v = HasExpiry
        .and_then(Time::valid_at(ts(1000)))
        .and_then(FromIssuer("example.com"))
        .and_then(ForAudience("my-app"));

    assert!(v.validate(&claims).is_ok());
}

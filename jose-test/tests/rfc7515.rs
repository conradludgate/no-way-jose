/// RFC 7515 Appendix A test vectors.
use base64ct::{Base64UrlUnpadded, Encoding};
use jose_core::validation::NoValidation;

// -- RFC 7515 A.1: JWS Using HMAC SHA-256 --

const HS256_TOKEN: &str = "\
    eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
    dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

const HS256_JWK_K: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

#[test]
fn hs256_verify_rfc7515_a1() {
    let key_bytes = Base64UrlUnpadded::decode_vec(HS256_JWK_K).unwrap();
    let key = jose_hmac::verifying_key(key_bytes);

    let token: jose_core::CompactJws<jose_hmac::Hs256, serde_json::Value> =
        HS256_TOKEN.parse().unwrap();

    let header = token.header().unwrap();
    assert_eq!(header.alg, "HS256");
    assert_eq!(header.typ.as_deref(), Some("JWT"));

    let unsealed = token
        .verify(&key, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(unsealed.claims["iss"], "joe");
    assert_eq!(unsealed.claims["exp"], 1300819380);
}

#[test]
fn hs256_roundtrip() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec());
    let vk = jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec());

    let claims = serde_json::json!({"sub": "1234567890", "name": "Test User"});

    let unsigned =
        jose_core::UnsignedToken::<jose_hmac::Hs256, _>::new(claims);
    let compact = unsigned.sign(&key).unwrap();

    let token_str = compact.to_string();
    let parsed: jose_core::CompactJws<jose_hmac::Hs256, serde_json::Value> =
        token_str.parse().unwrap();

    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(verified.claims["sub"], "1234567890");
    assert_eq!(verified.claims["name"], "Test User");
}

// -- RFC 7515 A.3: JWS Using ECDSA P-256 SHA-256 --

const ES256_TOKEN: &str = "\
    eyJhbGciOiJFUzI1NiJ9.\
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
    DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA\
    pmWQxfKTUJqPP3-Kg6NU1Q";

const ES256_JWK_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

#[test]
fn es256_verify_rfc7515_a3() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = jose_ecdsa::verifying_key_from_signing(&sk);

    let token: jose_core::CompactJws<jose_ecdsa::Es256, serde_json::Value> =
        ES256_TOKEN.parse().unwrap();

    let header = token.header().unwrap();
    assert_eq!(header.alg, "ES256");

    let unsealed = token
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(unsealed.claims["iss"], "joe");
    assert_eq!(unsealed.claims["exp"], 1300819380);
}

#[test]
fn es256_roundtrip() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = jose_ecdsa::verifying_key_from_signing(&sk);

    let claims = serde_json::json!({"sub": "test", "admin": true});

    let unsigned =
        jose_core::UnsignedToken::<jose_ecdsa::Es256, _>::new(claims);
    let compact = unsigned.sign(&sk).unwrap();

    let token_str = compact.to_string();
    let parsed: jose_core::CompactJws<jose_ecdsa::Es256, serde_json::Value> =
        token_str.parse().unwrap();

    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(verified.claims["sub"], "test");
    assert_eq!(verified.claims["admin"], true);
}

// -- Algorithm mismatch rejection --

#[test]
fn algorithm_mismatch_rejected() {
    // Try to parse an HS256 token as ES256 — should fail at FromStr.
    let result: Result<jose_core::CompactJws<jose_ecdsa::Es256, serde_json::Value>, _> =
        HS256_TOKEN.parse();
    assert!(result.is_err());
}

#[test]
fn es256_token_rejected_as_hs256() {
    let result: Result<jose_core::CompactJws<jose_hmac::Hs256, serde_json::Value>, _> =
        ES256_TOKEN.parse();
    assert!(result.is_err());
}

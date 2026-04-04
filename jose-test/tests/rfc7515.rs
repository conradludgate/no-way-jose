/// RFC 7515 Appendix A test vectors and compact JWS tests.
use base64ct::{Base64UrlUnpadded, Encoding};
use jose_core::JoseError;
use jose_core::json::{FromJson, JsonReader, JsonWriter, RawJson, ToJson};
use jose_core::validation::NoValidation;

// -- Test claim structs --

#[derive(Debug)]
struct RoundtripClaims {
    sub: String,
    name: String,
}

impl ToJson for RoundtripClaims {
    fn write_json(&self, buf: &mut Vec<u8>) {
        let mut w = JsonWriter::new();
        w.string("sub", &self.sub);
        w.string("name", &self.name);
        buf.extend_from_slice(&w.finish());
    }
}

impl FromJson for RoundtripClaims {
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, Box<dyn core::error::Error + Send + Sync>> {
        let mut reader = JsonReader::new(bytes)?;
        let mut sub = None;
        let mut name = None;
        while let Some(key) = reader.next_key()? {
            match key {
                "sub" => sub = Some(reader.read_string()?),
                "name" => name = Some(reader.read_string()?),
                _ => reader.skip_value()?,
            }
        }
        Ok(Self {
            sub: sub.ok_or(JoseError::InvalidToken("missing sub"))?,
            name: name.ok_or(JoseError::InvalidToken("missing name"))?,
        })
    }
}

#[derive(Debug)]
struct AdminClaims {
    sub: String,
    admin: bool,
}

impl ToJson for AdminClaims {
    fn write_json(&self, buf: &mut Vec<u8>) {
        let mut w = JsonWriter::new();
        w.string("sub", &self.sub);
        w.bool("admin", self.admin);
        buf.extend_from_slice(&w.finish());
    }
}

impl FromJson for AdminClaims {
    fn from_json_bytes(bytes: &[u8]) -> Result<Self, Box<dyn core::error::Error + Send + Sync>> {
        let mut reader = JsonReader::new(bytes)?;
        let mut sub = None;
        let mut admin = None;
        while let Some(key) = reader.next_key()? {
            match key {
                "sub" => sub = Some(reader.read_string()?),
                "admin" => admin = Some(reader.read_bool()?),
                _ => reader.skip_value()?,
            }
        }
        Ok(Self {
            sub: sub.ok_or(JoseError::InvalidToken("missing sub"))?,
            admin: admin.ok_or(JoseError::InvalidToken("missing admin"))?,
        })
    }
}

// -- Keys --

const ES256_JWK_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

// -- RFC 7515 A.1: the header contains \r\n whitespace, so our strict parser rejects it --

#[test]
fn rfc7515_a1_rejected_non_compact_header() {
    let token_str = "\
        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
        dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let result: Result<jose_core::CompactJws<jose_hmac::Hs256>, _> = token_str.parse();
    assert!(result.is_err());
}

// -- RFC 7515 A.3: ES256 header is compact, so it parses fine --

const ES256_TOKEN: &str = "\
    eyJhbGciOiJFUzI1NiJ9.\
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
    DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA\
    pmWQxfKTUJqPP3-Kg6NU1Q";

#[test]
fn es256_verify_rfc7515_a3() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = jose_ecdsa::verifying_key_from_signing(&sk);

    // Payload is non-compact but we use RawJson to skip payload parsing.
    let token: jose_core::CompactJws<jose_ecdsa::Es256, RawJson> = ES256_TOKEN.parse().unwrap();

    let header = token.header().unwrap();
    assert_eq!(header.alg, "ES256");

    let _unsealed = token
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
}

// -- Roundtrip tests --

#[test]
fn hs256_roundtrip() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let vk = jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();

    let claims = RoundtripClaims {
        sub: "1234567890".into(),
        name: "Test User".into(),
    };

    let unsigned = jose_core::UnsignedToken::<jose_hmac::Hs256, _>::new(claims);
    let compact = unsigned.sign(&key).unwrap();

    let token_str = compact.to_string();
    let parsed: jose_core::CompactJws<jose_hmac::Hs256, RoundtripClaims> =
        token_str.parse().unwrap();

    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(verified.claims.sub, "1234567890");
    assert_eq!(verified.claims.name, "Test User");
}

#[test]
fn es256_roundtrip() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = jose_ecdsa::verifying_key_from_signing(&sk);

    let claims = AdminClaims {
        sub: "test".into(),
        admin: true,
    };

    let unsigned = jose_core::UnsignedToken::<jose_ecdsa::Es256, _>::new(claims);
    let compact = unsigned.sign(&sk).unwrap();

    let token_str = compact.to_string();
    let parsed: jose_core::CompactJws<jose_ecdsa::Es256, AdminClaims> = token_str.parse().unwrap();

    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(verified.claims.sub, "test");
    assert!(verified.claims.admin);
}

// -- ES384 roundtrip --

#[test]
fn es384_roundtrip() {
    // A fixed 48-byte P-384 scalar (valid private key for testing).
    let sk_bytes: [u8; 48] = [
        0x6B, 0x9D, 0x3D, 0xAD, 0x2E, 0x1B, 0x8C, 0x1C, 0x05, 0xB1, 0x98, 0x75,
        0xB6, 0x65, 0x9F, 0x4D, 0xE2, 0x3C, 0x3B, 0x66, 0x7B, 0xF2, 0x97, 0xBA,
        0x9A, 0xA4, 0x77, 0x40, 0x78, 0x71, 0x37, 0xD8, 0x96, 0xD5, 0x72, 0x4E,
        0x4C, 0x70, 0xA8, 0x25, 0xF8, 0x72, 0xC9, 0xEA, 0x60, 0xD2, 0xED, 0xF5,
    ];
    let sk = jose_ecdsa::es384::signing_key_from_bytes(&sk_bytes).unwrap();
    let vk = jose_ecdsa::es384::verifying_key_from_signing(&sk);

    let claims = RoundtripClaims {
        sub: "es384".into(),
        name: "Test".into(),
    };
    let token_str = jose_core::UnsignedToken::<jose_ecdsa::Es384, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let parsed: jose_core::CompactJws<jose_ecdsa::Es384, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "es384");
}

// -- HS384 / HS512 roundtrips --

#[test]
fn hs384_roundtrip() {
    let key_bytes = vec![0xABu8; 48];
    let key = jose_hmac::hs384::symmetric_key(key_bytes.clone()).unwrap();
    let vk = jose_hmac::hs384::verifying_key(key_bytes).unwrap();

    let claims = RoundtripClaims {
        sub: "hs384".into(),
        name: "Test".into(),
    };
    let token_str = jose_core::UnsignedToken::<jose_hmac::Hs384, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let parsed: jose_core::CompactJws<jose_hmac::Hs384, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "hs384");
}

#[test]
fn hs512_roundtrip() {
    let key_bytes = vec![0xCDu8; 64];
    let key = jose_hmac::hs512::symmetric_key(key_bytes.clone()).unwrap();
    let vk = jose_hmac::hs512::verifying_key(key_bytes).unwrap();

    let claims = RoundtripClaims {
        sub: "hs512".into(),
        name: "Test".into(),
    };
    let token_str = jose_core::UnsignedToken::<jose_hmac::Hs512, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let parsed: jose_core::CompactJws<jose_hmac::Hs512, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "hs512");
}

#[test]
fn hs384_rejects_short_key() {
    assert!(jose_hmac::hs384::symmetric_key(vec![0u8; 47]).is_err());
    assert!(jose_hmac::hs384::symmetric_key(vec![0u8; 48]).is_ok());
}

#[test]
fn hs512_rejects_short_key() {
    assert!(jose_hmac::hs512::symmetric_key(vec![0u8; 63]).is_err());
    assert!(jose_hmac::hs512::symmetric_key(vec![0u8; 64]).is_ok());
}

// -- Algorithm mismatch rejection --

#[test]
fn algorithm_mismatch_rejected() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let claims = RoundtripClaims {
        sub: "x".into(),
        name: "y".into(),
    };
    let token_str = jose_core::UnsignedToken::<jose_hmac::Hs256, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let result: Result<jose_core::CompactJws<jose_ecdsa::Es256>, _> = token_str.parse();
    assert!(result.is_err());
}

#[test]
fn es256_token_rejected_as_hs256() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let claims = AdminClaims {
        sub: "x".into(),
        admin: false,
    };
    let token_str = jose_core::UnsignedToken::<jose_ecdsa::Es256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let result: Result<jose_core::CompactJws<jose_hmac::Hs256>, _> = token_str.parse();
    assert!(result.is_err());
}

// -- typ validation --

#[test]
fn require_typ_validates() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let header_b64 = jose_core::header::HeaderBuilder::new("HS256")
        .typ("JWT")
        .build();
    let claims = RoundtripClaims {
        sub: "x".into(),
        name: "y".into(),
    };
    let token_str =
        jose_core::UnsignedToken::<jose_hmac::Hs256, _>::with_header(header_b64, claims)
            .sign(&key)
            .unwrap()
            .to_string();

    let token: jose_core::CompactJws<jose_hmac::Hs256> = token_str.parse().unwrap();
    assert!(token.require_typ("JWT").is_ok());

    let token: jose_core::CompactJws<jose_hmac::Hs256> = token_str.parse().unwrap();
    assert!(token.require_typ("jwt").is_ok());

    let token: jose_core::CompactJws<jose_hmac::Hs256> = token_str.parse().unwrap();
    assert!(token.require_typ("at+jwt").is_err());
}

#[test]
fn require_typ_rejects_missing() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let claims = AdminClaims {
        sub: "x".into(),
        admin: false,
    };
    let token_str = jose_core::UnsignedToken::<jose_ecdsa::Es256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let token: jose_core::CompactJws<jose_ecdsa::Es256> = token_str.parse().unwrap();
    assert!(token.require_typ("JWT").is_err());
}

// -- UntypedCompactJws --

#[test]
fn untyped_parses_and_dispatches_hs256() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let vk = jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let claims = RoundtripClaims {
        sub: "joe".into(),
        name: "Joe".into(),
    };
    let token_str = jose_core::UnsignedToken::<jose_hmac::Hs256, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let untyped: jose_core::UntypedCompactJws<RoundtripClaims> = token_str.parse().unwrap();
    assert_eq!(untyped.alg(), "HS256");

    let typed = untyped.into_typed::<jose_hmac::Hs256>().unwrap();
    let unsealed = typed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(unsealed.claims.sub, "joe");
}

#[test]
fn untyped_parses_and_dispatches_es256() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = jose_ecdsa::verifying_key_from_signing(&sk);

    let claims = AdminClaims {
        sub: "joe".into(),
        admin: true,
    };
    let token_str = jose_core::UnsignedToken::<jose_ecdsa::Es256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let untyped: jose_core::UntypedCompactJws<AdminClaims> = token_str.parse().unwrap();
    assert_eq!(untyped.alg(), "ES256");

    let typed = untyped.into_typed::<jose_ecdsa::Es256>().unwrap();
    let unsealed = typed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(unsealed.claims.sub, "joe");
}

#[test]
fn untyped_rejects_wrong_typed_conversion() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let claims = RoundtripClaims {
        sub: "x".into(),
        name: "y".into(),
    };
    let token_str = jose_core::UnsignedToken::<jose_hmac::Hs256, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let untyped: jose_core::UntypedCompactJws = token_str.parse().unwrap();
    assert!(untyped.into_typed::<jose_ecdsa::Es256>().is_err());
}

#[test]
fn untyped_dynamic_dispatch() {
    let key = jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let hmac_vk = jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();

    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let ecdsa_vk = jose_ecdsa::verifying_key_from_signing(&sk);

    let hs_token = jose_core::UnsignedToken::<jose_hmac::Hs256, _>::new(RoundtripClaims {
        sub: "joe".into(),
        name: "Joe".into(),
    })
    .sign(&key)
    .unwrap()
    .to_string();

    let es_token = jose_core::UnsignedToken::<jose_ecdsa::Es256, _>::new(AdminClaims {
        sub: "joe".into(),
        admin: true,
    })
    .sign(&sk)
    .unwrap()
    .to_string();

    for token_str in [hs_token.as_str(), es_token.as_str()] {
        let untyped: jose_core::UntypedCompactJws = token_str.parse().unwrap();
        let result = match untyped.alg() {
            "HS256" => untyped
                .into_typed::<jose_hmac::Hs256>()
                .and_then(|t| t.verify(&hmac_vk, &NoValidation::dangerous_no_validation()))
                .map(|_| ()),
            "ES256" => untyped
                .into_typed::<jose_ecdsa::Es256>()
                .and_then(|t| t.verify(&ecdsa_vk, &NoValidation::dangerous_no_validation()))
                .map(|_| ()),
            other => panic!("unexpected alg: {other}"),
        };
        assert!(result.is_ok());
    }
}

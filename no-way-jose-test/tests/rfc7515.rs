/// RFC 7515 Appendix A test vectors and compact JWS tests.
use base64ct::{Base64UrlUnpadded, Encoding};
use no_way_jose_core::JoseError;
use no_way_jose_core::json::{FromJson, JsonReader, JsonWriter, RawJson, ToJson};
use no_way_jose_core::validation::NoValidation;

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
    let result: Result<no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256>, _> =
        token_str.parse();
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
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = no_way_jose_ecdsa::verifying_key_from_signing(&sk);

    // Payload is non-compact but we use RawJson to skip payload parsing.
    let token: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256, RawJson> =
        ES256_TOKEN.parse().unwrap();

    let header = token.header().unwrap();
    assert_eq!(header.alg, "ES256");

    let _unsealed = token
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
}

// -- RFC 7520 Section 4.4: HS256 with kid --

const RFC7520_HS256_TOKEN: &str = "\
    eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.\
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.\
    s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

#[test]
fn rfc7520_hs256_verify() {
    let key_bytes =
        Base64UrlUnpadded::decode_vec("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg").unwrap();
    let vk = no_way_jose_hmac::verifying_key(key_bytes).unwrap();

    let token: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256, RawJson> =
        RFC7520_HS256_TOKEN.parse().unwrap();
    let header = token.header().unwrap();
    assert_eq!(header.alg, "HS256");
    assert_eq!(
        header.kid.as_deref(),
        Some("018c0ae5-4d9b-471b-bfd6-eef314bc7037")
    );

    let _unsealed = token
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
}

// -- RFC 7515 A.2: RS256 --

fn bu(bytes: &[u8]) -> rsa::BoxedUint {
    let bits = (bytes.len() as u32) * 8;
    let precision = (bits + 63) & !63;
    rsa::BoxedUint::from_be_slice(bytes, precision).unwrap()
}

fn rfc7515_a2_rsa_private_key() -> rsa::RsaPrivateKey {
    let n = bu(&Base64UrlUnpadded::decode_vec(
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\
         HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\
         D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\
         SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\
         MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\
         NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    )
    .unwrap());
    let e = bu(&Base64UrlUnpadded::decode_vec("AQAB").unwrap());
    let d = bu(&Base64UrlUnpadded::decode_vec(
        "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I\
         jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0\
         BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn\
         439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT\
         CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh\
         BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    )
    .unwrap());
    let primes = vec![
        bu(&Base64UrlUnpadded::decode_vec(
            "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi\
             YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG\
             BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
        )
        .unwrap()),
        bu(&Base64UrlUnpadded::decode_vec(
            "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa\
             ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA\
             -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
        )
        .unwrap()),
    ];
    rsa::RsaPrivateKey::from_components(n, e, d, primes).unwrap()
}

const RS256_TOKEN: &str = "\
    eyJhbGciOiJSUzI1NiJ9.\
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
    cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7\
    AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4\
    BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K\
    0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv\
    hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB\
    p0igcN_IoypGlUPQGe77Rw";

#[test]
fn rs256_verify_rfc7515_a2() {
    let sk = rfc7515_a2_rsa_private_key();
    let vk = no_way_jose_rsa::verifying_key(rsa::RsaPublicKey::from(&sk));

    let token: no_way_jose_core::CompactJws<no_way_jose_rsa::Rs256, RawJson> =
        RS256_TOKEN.parse().unwrap();
    let header = token.header().unwrap();
    assert_eq!(header.alg, "RS256");

    let _unsealed = token
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
}

#[test]
fn rs256_roundtrip() {
    let sk_inner = rfc7515_a2_rsa_private_key();
    let sk = no_way_jose_rsa::signing_key(sk_inner.clone());
    let vk = no_way_jose_rsa::verifying_key_from_signing(&sk);

    let claims = RoundtripClaims {
        sub: "rs256".into(),
        name: "Test".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_rsa::Rs256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let parsed: no_way_jose_core::CompactJws<no_way_jose_rsa::Rs256, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "rs256");
}

#[test]
fn ps256_roundtrip() {
    let sk_inner = rfc7515_a2_rsa_private_key();
    let sk = no_way_jose_rsa::ps256::signing_key(sk_inner);
    let vk = no_way_jose_rsa::ps256::verifying_key_from_signing(&sk);

    let claims = RoundtripClaims {
        sub: "ps256".into(),
        name: "Test".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_rsa::Ps256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let parsed: no_way_jose_core::CompactJws<no_way_jose_rsa::Ps256, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "ps256");
}

// -- Roundtrip tests --

#[test]
fn hs256_roundtrip() {
    let key =
        no_way_jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let vk = no_way_jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();

    let claims = RoundtripClaims {
        sub: "1234567890".into(),
        name: "Test User".into(),
    };

    let unsigned = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(claims);
    let compact = unsigned.sign(&key).unwrap();

    let token_str = compact.to_string();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256, RoundtripClaims> =
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
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = no_way_jose_ecdsa::verifying_key_from_signing(&sk);

    let claims = AdminClaims {
        sub: "test".into(),
        admin: true,
    };

    let unsigned = no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es256, _>::new(claims);
    let compact = unsigned.sign(&sk).unwrap();

    let token_str = compact.to_string();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256, AdminClaims> =
        token_str.parse().unwrap();

    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();

    assert_eq!(verified.claims.sub, "test");
    assert!(verified.claims.admin);
}

// -- RFC 8037 A.4/A.5: EdDSA Ed25519 --

const EDDSA_TOKEN: &str = "\
    eyJhbGciOiJFZERTQSJ9.\
    RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
    hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

#[test]
fn eddsa_verify_rfc8037() {
    let d_bytes =
        Base64UrlUnpadded::decode_vec("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
    let d: [u8; 32] = d_bytes.try_into().unwrap();
    let sk = no_way_jose_eddsa::signing_key_from_bytes(&d);
    let vk = no_way_jose_eddsa::verifying_key_from_signing(&sk);

    let token: no_way_jose_core::CompactJws<no_way_jose_eddsa::EdDsa, RawJson> =
        EDDSA_TOKEN.parse().unwrap();
    let header = token.header().unwrap();
    assert_eq!(header.alg, "EdDSA");

    let _unsealed = token
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
}

#[test]
fn eddsa_roundtrip() {
    let d_bytes =
        Base64UrlUnpadded::decode_vec("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
    let d: [u8; 32] = d_bytes.try_into().unwrap();
    let sk = no_way_jose_eddsa::signing_key_from_bytes(&d);
    let vk = no_way_jose_eddsa::verifying_key_from_signing(&sk);

    let claims = RoundtripClaims {
        sub: "eddsa".into(),
        name: "Test".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_eddsa::EdDsa, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let parsed: no_way_jose_core::CompactJws<no_way_jose_eddsa::EdDsa, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "eddsa");
}

// -- ES384 roundtrip --

#[test]
fn es384_roundtrip() {
    // A fixed 48-byte P-384 scalar (valid private key for testing).
    let sk_bytes: [u8; 48] = [
        0x6B, 0x9D, 0x3D, 0xAD, 0x2E, 0x1B, 0x8C, 0x1C, 0x05, 0xB1, 0x98, 0x75, 0xB6, 0x65, 0x9F,
        0x4D, 0xE2, 0x3C, 0x3B, 0x66, 0x7B, 0xF2, 0x97, 0xBA, 0x9A, 0xA4, 0x77, 0x40, 0x78, 0x71,
        0x37, 0xD8, 0x96, 0xD5, 0x72, 0x4E, 0x4C, 0x70, 0xA8, 0x25, 0xF8, 0x72, 0xC9, 0xEA, 0x60,
        0xD2, 0xED, 0xF5,
    ];
    let sk = no_way_jose_ecdsa::es384::signing_key_from_bytes(&sk_bytes).unwrap();
    let vk = no_way_jose_ecdsa::es384::verifying_key_from_signing(&sk);

    let claims = RoundtripClaims {
        sub: "es384".into(),
        name: "Test".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es384, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let parsed: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es384, RoundtripClaims> =
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
    let key = no_way_jose_hmac::hs384::symmetric_key(key_bytes.clone()).unwrap();
    let vk = no_way_jose_hmac::hs384::verifying_key(key_bytes).unwrap();

    let claims = RoundtripClaims {
        sub: "hs384".into(),
        name: "Test".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs384, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let parsed: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs384, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "hs384");
}

#[test]
fn hs512_roundtrip() {
    let key_bytes = vec![0xCDu8; 64];
    let key = no_way_jose_hmac::hs512::symmetric_key(key_bytes.clone()).unwrap();
    let vk = no_way_jose_hmac::hs512::verifying_key(key_bytes).unwrap();

    let claims = RoundtripClaims {
        sub: "hs512".into(),
        name: "Test".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs512, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let parsed: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs512, RoundtripClaims> =
        token_str.parse().unwrap();
    let verified = parsed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(verified.claims.sub, "hs512");
}

#[test]
fn hs384_rejects_short_key() {
    assert!(no_way_jose_hmac::hs384::symmetric_key(vec![0u8; 47]).is_err());
    assert!(no_way_jose_hmac::hs384::symmetric_key(vec![0u8; 48]).is_ok());
}

#[test]
fn hs512_rejects_short_key() {
    assert!(no_way_jose_hmac::hs512::symmetric_key(vec![0u8; 63]).is_err());
    assert!(no_way_jose_hmac::hs512::symmetric_key(vec![0u8; 64]).is_ok());
}

// -- Algorithm mismatch rejection --

#[test]
fn algorithm_mismatch_rejected() {
    let key =
        no_way_jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let claims = RoundtripClaims {
        sub: "x".into(),
        name: "y".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let result: Result<no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256>, _> =
        token_str.parse();
    assert!(result.is_err());
}

#[test]
fn es256_token_rejected_as_hs256() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let claims = AdminClaims {
        sub: "x".into(),
        admin: false,
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let result: Result<no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256>, _> =
        token_str.parse();
    assert!(result.is_err());
}

// -- typ validation --

#[test]
fn require_typ_validates() {
    let key =
        no_way_jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let header_b64 = no_way_jose_core::header::HeaderBuilder::new("HS256")
        .typ("JWT")
        .build();
    let claims = RoundtripClaims {
        sub: "x".into(),
        name: "y".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::with_header(
        header_b64, claims,
    )
    .sign(&key)
    .unwrap()
    .to_string();

    let token: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256> = token_str.parse().unwrap();
    assert!(token.require_typ("JWT").is_ok());

    let token: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256> = token_str.parse().unwrap();
    assert!(token.require_typ("jwt").is_ok());

    let token: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256> = token_str.parse().unwrap();
    assert!(token.require_typ("at+jwt").is_err());
}

#[test]
fn require_typ_rejects_missing() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let claims = AdminClaims {
        sub: "x".into(),
        admin: false,
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let token: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256> = token_str.parse().unwrap();
    assert!(token.require_typ("JWT").is_err());
}

// -- UntypedCompactJws --

#[test]
fn untyped_parses_and_dispatches_hs256() {
    let key =
        no_way_jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let vk = no_way_jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let claims = RoundtripClaims {
        sub: "joe".into(),
        name: "Joe".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let untyped: no_way_jose_core::UntypedCompactJws<RoundtripClaims> = token_str.parse().unwrap();
    assert_eq!(untyped.alg(), "HS256");

    let typed = untyped.into_typed::<no_way_jose_hmac::Hs256>().unwrap();
    let unsealed = typed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(unsealed.claims.sub, "joe");
}

#[test]
fn untyped_parses_and_dispatches_es256() {
    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let vk = no_way_jose_ecdsa::verifying_key_from_signing(&sk);

    let claims = AdminClaims {
        sub: "joe".into(),
        admin: true,
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es256, _>::new(claims)
        .sign(&sk)
        .unwrap()
        .to_string();

    let untyped: no_way_jose_core::UntypedCompactJws<AdminClaims> = token_str.parse().unwrap();
    assert_eq!(untyped.alg(), "ES256");

    let typed = untyped.into_typed::<no_way_jose_ecdsa::Es256>().unwrap();
    let unsealed = typed
        .verify(&vk, &NoValidation::dangerous_no_validation())
        .unwrap();
    assert_eq!(unsealed.claims.sub, "joe");
}

#[test]
fn untyped_rejects_wrong_typed_conversion() {
    let key =
        no_way_jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let claims = RoundtripClaims {
        sub: "x".into(),
        name: "y".into(),
    };
    let token_str = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(claims)
        .sign(&key)
        .unwrap()
        .to_string();

    let untyped: no_way_jose_core::UntypedCompactJws = token_str.parse().unwrap();
    assert!(untyped.into_typed::<no_way_jose_ecdsa::Es256>().is_err());
}

#[test]
fn untyped_dynamic_dispatch() {
    let key =
        no_way_jose_hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();
    let hmac_vk =
        no_way_jose_hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec()).unwrap();

    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&d_bytes).unwrap();
    let ecdsa_vk = no_way_jose_ecdsa::verifying_key_from_signing(&sk);

    let hs_token =
        no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(RoundtripClaims {
            sub: "joe".into(),
            name: "Joe".into(),
        })
        .sign(&key)
        .unwrap()
        .to_string();

    let es_token =
        no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es256, _>::new(AdminClaims {
            sub: "joe".into(),
            admin: true,
        })
        .sign(&sk)
        .unwrap()
        .to_string();

    for token_str in [hs_token.as_str(), es_token.as_str()] {
        let untyped: no_way_jose_core::UntypedCompactJws = token_str.parse().unwrap();
        let result = match untyped.alg() {
            "HS256" => untyped
                .into_typed::<no_way_jose_hmac::Hs256>()
                .and_then(|t| t.verify(&hmac_vk, &NoValidation::dangerous_no_validation()))
                .map(|_| ()),
            "ES256" => untyped
                .into_typed::<no_way_jose_ecdsa::Es256>()
                .and_then(|t| t.verify(&ecdsa_vk, &NoValidation::dangerous_no_validation()))
                .map(|_| ()),
            other => panic!("unexpected alg: {other}"),
        };
        assert!(result.is_ok());
    }
}

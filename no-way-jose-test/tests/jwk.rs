/// JWK tests: RFC 7517/7638 test vectors and round-trip tests.
use no_way_jose_core::jwk::{EcCurve, FromJwk, Jwk, JwkParams, JwkSet, OkpCurve, ToJwk};

// ====================================================================
// RFC 7517 Appendix A test vectors
// ====================================================================

/// RFC 7517 Appendix A.1 — EC public key
#[test]
fn rfc7517_ec_public_key() {
    let json = br#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"sig","kid":"Public key used in JWS spec Appendix A.3 example"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    assert_eq!(jwk.kty(), "EC");
    assert_eq!(
        jwk.kid.as_deref(),
        Some("Public key used in JWS spec Appendix A.3 example")
    );
    match &jwk.key {
        JwkParams::Ec(p) => {
            assert_eq!(p.crv, EcCurve::P256);
            assert_eq!(p.x.len(), 32);
            assert_eq!(p.y.len(), 32);
            assert!(p.d.is_none());
        }
        _ => panic!("expected EC params"),
    }
}

/// RFC 7517 Appendix A.2 — EC private key
#[test]
fn rfc7517_ec_private_key() {
    let json = br#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffS1BSyVKhrlRhLv_HA0V1u3oFSVM","use":"sig","kid":"Appendix A.2 example"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    match &jwk.key {
        JwkParams::Ec(p) => {
            assert!(p.d.is_some());
            assert_eq!(p.d.as_ref().unwrap().len(), 32);
        }
        _ => panic!("expected EC params"),
    }
}

/// RFC 7517 Appendix A.1 — RSA public key
#[test]
fn rfc7517_rsa_public_key() {
    let json = br#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    assert_eq!(jwk.kty(), "RSA");
    assert_eq!(jwk.kid.as_deref(), Some("2011-04-29"));
    assert_eq!(jwk.alg.as_deref(), Some("RS256"));
    match &jwk.key {
        JwkParams::Rsa(p) => {
            assert!(!p.n.is_empty());
            assert_eq!(p.e, &[1, 0, 1]);
            assert!(p.prv.is_none());
        }
        _ => panic!("expected RSA params"),
    }
}

/// RFC 7517 Appendix A.3 — symmetric (oct) key
#[test]
fn rfc7517_symmetric_key() {
    let json = br#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    assert_eq!(jwk.kty(), "oct");
    assert_eq!(jwk.alg.as_deref(), Some("A128KW"));
    match &jwk.key {
        JwkParams::Oct(p) => {
            assert_eq!(p.k.len(), 16);
        }
        _ => panic!("expected oct params"),
    }
}

/// RFC 7517 Appendix B — JWK Set
#[test]
fn rfc7517_jwk_set() {
    let json = br#"{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"enc","kid":"1"},{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}]}"#;
    let set = JwkSet::from_json_bytes(json).unwrap();
    assert_eq!(set.keys.len(), 2);
    assert_eq!(set.find_by_kid("1").unwrap().kty(), "EC");
    assert_eq!(set.find_by_kid("2011-04-29").unwrap().kty(), "RSA");
    assert!(set.find_by_kid("nonexistent").is_none());

    // Roundtrip
    let bytes = set.to_json_bytes();
    let parsed = JwkSet::from_json_bytes(&bytes).unwrap();
    assert_eq!(parsed.keys.len(), 2);
}

// ====================================================================
// RFC 7638 thumbprint test vector
// ====================================================================

#[test]
fn rfc7638_thumbprint() {
    let json = br#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    let canonical = jwk.thumbprint_canonical_json();

    // The RFC 7638 §3.1 expected thumbprint (base64url of SHA-256):
    // NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&canonical);
    let b64 = no_way_jose_core::base64url::encode(&hash);
    assert_eq!(b64, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
}

// ====================================================================
// Round-trip tests: key -> JWK -> key
// ====================================================================

#[test]
fn hmac_jwk_roundtrip() {
    let key_bytes = vec![0xABu8; 32];
    let sk = no_way_jose_hmac::symmetric_key(key_bytes.clone()).unwrap();
    let jwk = sk.to_jwk();
    assert_eq!(jwk.kty(), "oct");
    assert_eq!(jwk.alg.as_deref(), Some("HS256"));

    let sk2: no_way_jose_hmac::SigningKey = FromJwk::from_jwk(&jwk).unwrap();
    let vk: no_way_jose_hmac::VerifyingKey = FromJwk::from_jwk(&jwk).unwrap();

    let token = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(
        no_way_jose_core::json::RawJson(br#"{"sub":"test"}"#.to_vec()),
    )
    .sign(&sk)
    .unwrap();

    let compact_str = token.to_string();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256> =
        compact_str.parse().unwrap();
    parsed
        .verify(
            &vk,
            &no_way_jose_core::validation::NoValidation::dangerous_no_validation(),
        )
        .unwrap();

    let token2 = no_way_jose_core::UnsignedToken::<no_way_jose_hmac::Hs256, _>::new(
        no_way_jose_core::json::RawJson(br#"{"sub":"test2"}"#.to_vec()),
    )
    .sign(&sk2)
    .unwrap();
    let parsed2: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256> =
        token2.to_string().parse().unwrap();
    parsed2
        .verify(
            &vk,
            &no_way_jose_core::validation::NoValidation::dangerous_no_validation(),
        )
        .unwrap();
}

#[test]
fn ecdsa_es256_jwk_roundtrip() {
    let sk = no_way_jose_ecdsa::signing_key_from_bytes(&[42u8; 32]).unwrap();
    let vk = no_way_jose_ecdsa::verifying_key_from_signing(&sk);

    let sk_jwk = sk.to_jwk();
    assert_eq!(sk_jwk.kty(), "EC");
    assert_eq!(sk_jwk.alg.as_deref(), Some("ES256"));
    match &sk_jwk.key {
        JwkParams::Ec(p) => {
            assert_eq!(p.crv, EcCurve::P256);
            assert!(p.d.is_some());
        }
        _ => panic!("expected EC params"),
    }

    let vk_jwk = vk.to_jwk();
    match &vk_jwk.key {
        JwkParams::Ec(p) => assert!(p.d.is_none()),
        _ => panic!("expected EC params"),
    }

    let sk2: no_way_jose_ecdsa::SigningKey = FromJwk::from_jwk(&sk_jwk).unwrap();
    let vk2: no_way_jose_ecdsa::VerifyingKey = FromJwk::from_jwk(&vk_jwk).unwrap();

    let token = no_way_jose_core::UnsignedToken::<no_way_jose_ecdsa::Es256, _>::new(
        no_way_jose_core::json::RawJson(br#"{"sub":"ec"}"#.to_vec()),
    )
    .sign(&sk2)
    .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256> =
        token.to_string().parse().unwrap();
    parsed
        .verify(
            &vk2,
            &no_way_jose_core::validation::NoValidation::dangerous_no_validation(),
        )
        .unwrap();
}

#[test]
fn eddsa_jwk_roundtrip() {
    let sk = no_way_jose_eddsa::signing_key_from_bytes(&[7u8; 32]);
    let vk = no_way_jose_eddsa::verifying_key_from_signing(&sk);

    let sk_jwk = sk.to_jwk();
    assert_eq!(sk_jwk.kty(), "OKP");
    assert_eq!(sk_jwk.alg.as_deref(), Some("EdDSA"));
    match &sk_jwk.key {
        JwkParams::Okp(p) => {
            assert_eq!(p.crv, OkpCurve::Ed25519);
            assert!(p.d.is_some());
        }
        _ => panic!("expected OKP params"),
    }

    let vk_jwk = vk.to_jwk();
    match &vk_jwk.key {
        JwkParams::Okp(p) => assert!(p.d.is_none()),
        _ => panic!("expected OKP params"),
    }

    let sk2: no_way_jose_eddsa::SigningKey = FromJwk::from_jwk(&sk_jwk).unwrap();
    let vk2: no_way_jose_eddsa::VerifyingKey = FromJwk::from_jwk(&vk_jwk).unwrap();

    let token = no_way_jose_core::UnsignedToken::<no_way_jose_eddsa::EdDsa, _>::new(
        no_way_jose_core::json::RawJson(br#"{"sub":"ed"}"#.to_vec()),
    )
    .sign(&sk2)
    .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_eddsa::EdDsa> =
        token.to_string().parse().unwrap();
    parsed
        .verify(
            &vk2,
            &no_way_jose_core::validation::NoValidation::dangerous_no_validation(),
        )
        .unwrap();
}

#[test]
fn rsa_rs256_jwk_roundtrip() {
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = priv_key.to_public_key();

    let sk = no_way_jose_rsa::signing_key(priv_key);
    let vk = no_way_jose_rsa::verifying_key(pub_key);

    let sk_jwk = sk.to_jwk();
    assert_eq!(sk_jwk.kty(), "RSA");
    assert_eq!(sk_jwk.alg.as_deref(), Some("RS256"));
    match &sk_jwk.key {
        JwkParams::Rsa(p) => {
            assert!(!p.n.is_empty());
            assert!(p.prv.is_some());
        }
        _ => panic!("expected RSA params"),
    }

    let vk_jwk = vk.to_jwk();
    match &vk_jwk.key {
        JwkParams::Rsa(p) => assert!(p.prv.is_none()),
        _ => panic!("expected RSA params"),
    }

    let sk2: no_way_jose_rsa::SigningKey = FromJwk::from_jwk(&sk_jwk).unwrap();
    let vk2: no_way_jose_rsa::VerifyingKey = FromJwk::from_jwk(&vk_jwk).unwrap();

    let token = no_way_jose_core::UnsignedToken::<no_way_jose_rsa::Rs256, _>::new(
        no_way_jose_core::json::RawJson(br#"{"sub":"rsa"}"#.to_vec()),
    )
    .sign(&sk2)
    .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_rsa::Rs256> =
        token.to_string().parse().unwrap();
    parsed
        .verify(
            &vk2,
            &no_way_jose_core::validation::NoValidation::dangerous_no_validation(),
        )
        .unwrap();
}

#[test]
fn aes_kw_jwk_roundtrip() {
    let key_bytes = vec![0x42u8; 16];
    let ek = no_way_jose_aes_kw::a128kw::encryption_key(key_bytes.clone()).unwrap();
    let jwk = ek.to_jwk();
    assert_eq!(jwk.kty(), "oct");
    assert_eq!(jwk.alg.as_deref(), Some("A128KW"));
    match &jwk.key {
        JwkParams::Oct(p) => assert_eq!(p.k, key_bytes),
        _ => panic!("expected oct params"),
    }

    let dk: no_way_jose_aes_kw::a128kw::DecryptionKey = FromJwk::from_jwk(&jwk).unwrap();
    assert_eq!(dk.inner(), &key_bytes);
}

#[test]
fn ecdh_es_jwk_roundtrip() {
    let sk_bytes = [99u8; 32];
    let secret_key = p256::SecretKey::from_slice(&sk_bytes).unwrap();
    let public_key = secret_key.public_key();

    let ek = no_way_jose_ecdh_es::ecdh_es::encryption_key(no_way_jose_ecdh_es::EcPublicKey::P256(
        public_key,
    ));
    let jwk = ek.to_jwk();
    assert_eq!(jwk.kty(), "EC");
    assert_eq!(jwk.alg.as_deref(), Some("ECDH-ES"));

    let ek2: no_way_jose_core::EncryptionKey<no_way_jose_ecdh_es::EcdhEs> =
        FromJwk::from_jwk(&jwk).unwrap();
    let jwk2 = ek2.to_jwk();
    match (&jwk.key, &jwk2.key) {
        (JwkParams::Ec(a), JwkParams::Ec(b)) => {
            assert_eq!(a.crv, b.crv);
            assert_eq!(a.x, b.x);
            assert_eq!(a.y, b.y);
        }
        _ => panic!("expected EC params"),
    }
}

/// Verify that JWK with wrong algorithm is rejected
#[test]
fn rejects_wrong_algorithm() {
    let key_bytes = vec![0xABu8; 32];
    let sk = no_way_jose_hmac::symmetric_key(key_bytes).unwrap();
    let mut jwk = sk.to_jwk();
    jwk.alg = Some("HS384".into());

    let result: Result<no_way_jose_hmac::SigningKey, _> = FromJwk::from_jwk(&jwk);
    assert!(result.is_err());
}

/// Verify that JWK with wrong key type is rejected
#[test]
fn rejects_wrong_kty() {
    let json = br#"{"kty":"oct","k":"dGVzdA"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    let result: Result<no_way_jose_ecdsa::VerifyingKey, _> = FromJwk::from_jwk(&jwk);
    assert!(result.is_err());
}

/// RFC 7520 §3.1 — EC key
#[test]
fn rfc7520_ec_key_parsing() {
    let json = br#"{"kty":"EC","kid":"bilbo.baggins@hobbiton.example","use":"enc","crv":"P-256","x":"WbbaSStufflt7SVQJkePlz--CDAwSA76-4CJJ2r_9veo","y":"vOGjkIiB2dCFfghqwCqPT3qORag74pMUxCl1b9b1gFo"}"#;
    let jwk = Jwk::from_json_bytes(json).unwrap();
    assert_eq!(jwk.kid.as_deref(), Some("bilbo.baggins@hobbiton.example"));
    match &jwk.key {
        JwkParams::Ec(p) => assert_eq!(p.crv, EcCurve::P256),
        _ => panic!("expected EC params"),
    }
}

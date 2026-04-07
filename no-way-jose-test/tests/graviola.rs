use no_way_jose_core::UnsignedToken;
use no_way_jose_core::error::JsonError;
use no_way_jose_core::json::{FromJson, JsonReader, JsonWriter, ToJson};
use no_way_jose_core::jwk::{EcCurve, FromJwk, JwkParams, OkpCurve, ToJwk};
use no_way_jose_core::validation::NoValidation;

#[derive(Debug)]
struct Claims {
    sub: String,
    admin: bool,
}

impl ToJson for Claims {
    fn write_json(&self, buf: &mut String) {
        let mut w = JsonWriter::new();
        w.string("sub", &self.sub);
        w.bool("admin", self.admin);
        buf.push_str(&w.finish());
    }
}

impl FromJson for Claims {
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
            sub: sub.ok_or(JsonError::MissingField)?,
            admin: admin.ok_or(JsonError::MissingField)?,
        })
    }
}

fn no_validation<T>() -> NoValidation<T> {
    NoValidation::dangerous_no_validation()
}

fn test_claims() -> Claims {
    Claims {
        sub: "graviola".into(),
        admin: true,
    }
}

// ====================================================================
// HMAC
// ====================================================================

#[test]
fn graviola_hs256_roundtrip() {
    let key =
        no_way_jose_graviola::hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec())
            .unwrap();
    let vk =
        no_way_jose_graviola::hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec())
            .unwrap();

    let compact = UnsignedToken::<no_way_jose_graviola::hmac::Hs256, _>::new(test_claims())
        .sign(&key)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::hmac::Hs256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
    assert!(verified.claims.admin);
}

#[test]
fn graviola_hs256_interop_with_rustcrypto() {
    let key_bytes = b"super-secret-key-for-testing-256".to_vec();

    let grav_key = no_way_jose_graviola::hmac::symmetric_key(key_bytes.clone()).unwrap();
    let compact = UnsignedToken::<no_way_jose_graviola::hmac::Hs256, _>::new(test_claims())
        .sign(&grav_key)
        .unwrap();

    let rc_vk = no_way_jose_hmac::verifying_key(key_bytes).unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&rc_vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
}

// ====================================================================
// EdDSA
// ====================================================================

#[test]
fn graviola_eddsa_roundtrip() {
    let sk = no_way_jose_graviola::eddsa::signing_key_from_bytes(&[42u8; 32]).unwrap();
    let vk = no_way_jose_graviola::eddsa::verifying_key_from_signing(&sk);

    let compact = UnsignedToken::<no_way_jose_graviola::eddsa::EdDsa, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::eddsa::EdDsa, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
}

#[test]
fn graviola_eddsa_interop_sign_grav_verify_rc() {
    let seed = [42u8; 32];

    let grav_sk = no_way_jose_graviola::eddsa::signing_key_from_bytes(&seed).unwrap();
    let compact = UnsignedToken::<no_way_jose_graviola::eddsa::EdDsa, _>::new(test_claims())
        .sign(&grav_sk)
        .unwrap();

    let rc_sk = no_way_jose_eddsa::signing_key_from_bytes(&seed);
    let rc_vk = no_way_jose_eddsa::verifying_key_from_signing(&rc_sk);
    let parsed: no_way_jose_core::CompactJws<no_way_jose_eddsa::EdDsa, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&rc_vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
}

// ====================================================================
// ECDSA
// ====================================================================

#[test]
fn graviola_es256_roundtrip() {
    use graviola::signing::ecdsa;
    let key = graviola::key_agreement::p256::StaticPrivateKey::new_random().unwrap();
    let pub_bytes = key.public_key_uncompressed();
    let sk: no_way_jose_graviola::ecdsa::SigningKey =
        no_way_jose_core::key::Key::new(ecdsa::SigningKey { private_key: key });
    let vk = no_way_jose_graviola::ecdsa::verifying_key_from_x962(&pub_bytes).unwrap();

    let compact = UnsignedToken::<no_way_jose_graviola::ecdsa::Es256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::ecdsa::Es256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
}

// ====================================================================
// RSA
// ====================================================================

#[test]
fn graviola_rs256_roundtrip() {
    use graviola::signing::rsa::KeySize;
    let key = graviola::signing::rsa::SigningKey::generate(KeySize::Rsa2048).unwrap();
    let vk_inner = key.public_key();

    let sk = no_way_jose_core::key::Key::new(key);
    let vk = no_way_jose_core::key::Key::new(vk_inner);

    let compact = UnsignedToken::<no_way_jose_graviola::rsa::Rs256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::rsa::Rs256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
}

#[test]
fn graviola_ps256_roundtrip() {
    use graviola::signing::rsa::KeySize;
    let key = graviola::signing::rsa::SigningKey::generate(KeySize::Rsa2048).unwrap();
    let vk_inner = key.public_key();

    let sk = no_way_jose_core::key::Key::<no_way_jose_graviola::rsa::Ps256, _>::new(key);
    let vk = no_way_jose_core::key::Key::<no_way_jose_graviola::rsa::Ps256, _>::new(vk_inner);

    let compact = UnsignedToken::<no_way_jose_graviola::rsa::Ps256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::rsa::Ps256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "graviola");
}

// ====================================================================
// AES-GCM (via dir)
// ====================================================================

#[test]
fn graviola_dir_a256gcm_roundtrip() {
    use no_way_jose_core::dir;
    use no_way_jose_core::purpose::Encrypted;
    use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};

    let key = vec![0x42u8; 32];
    let enc_key = dir::key(key.clone());
    let dec_key = dir::key(key);

    let claims = Claims {
        sub: "graviola-jwe".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<dir::Dir, no_way_jose_graviola::aes_gcm::A256Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, no_way_jose_graviola::aes_gcm::A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();
    assert_eq!(unsealed.claims.sub, "graviola-jwe");
    assert!(unsealed.claims.admin);
}

#[test]
fn graviola_dir_a128gcm_roundtrip() {
    use no_way_jose_core::dir;
    use no_way_jose_core::purpose::Encrypted;
    use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};

    let key = vec![0x42u8; 16];
    let enc_key = dir::key(key.clone());
    let dec_key = dir::key(key);

    let claims = Claims {
        sub: "grav-128".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<dir::Dir, no_way_jose_graviola::aes_gcm::A128Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, no_way_jose_graviola::aes_gcm::A128Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();
    assert_eq!(unsealed.claims.sub, "grav-128");
}

#[test]
fn graviola_aes_gcm_interop_encrypt_grav_decrypt_rc() {
    use no_way_jose_core::dir;
    use no_way_jose_core::purpose::Encrypted;
    use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};

    let key = vec![0x42u8; 32];
    let enc_key = dir::key(key.clone());
    let dec_key = dir::key(key);

    let claims = Claims {
        sub: "interop".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<dir::Dir, no_way_jose_graviola::aes_gcm::A256Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, no_way_jose_aes_gcm::A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();
    assert_eq!(unsealed.claims.sub, "interop");
}

// ====================================================================
// JWK round-trip tests
// ====================================================================

#[test]
fn graviola_ecdsa_es256_jwk_roundtrip() {
    use graviola::signing::ecdsa;

    let key = graviola::key_agreement::p256::StaticPrivateKey::new_random().unwrap();
    let pub_bytes = key.public_key_uncompressed();
    let sk: no_way_jose_graviola::ecdsa::SigningKey =
        no_way_jose_core::key::Key::new(ecdsa::SigningKey { private_key: key });
    let vk = no_way_jose_graviola::ecdsa::verifying_key_from_x962(&pub_bytes).unwrap();

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

    let sk2: no_way_jose_graviola::ecdsa::SigningKey = FromJwk::from_jwk(&sk_jwk).unwrap();
    let vk2: no_way_jose_graviola::ecdsa::VerifyingKey = FromJwk::from_jwk(&vk_jwk).unwrap();

    let token = UnsignedToken::<no_way_jose_graviola::ecdsa::Es256, _>::new(test_claims())
        .sign(&sk2)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::ecdsa::Es256, Claims> =
        token.to_string().parse().unwrap();
    parsed.verify(&vk2, &no_validation()).unwrap();
}

#[test]
fn graviola_ecdsa_es384_jwk_roundtrip() {
    use graviola::signing::ecdsa;

    let key = graviola::key_agreement::p384::StaticPrivateKey::new_random().unwrap();
    let pub_bytes = key.public_key_uncompressed();
    let sk: no_way_jose_core::SigningKey<no_way_jose_graviola::ecdsa::Es384> =
        no_way_jose_core::key::Key::new(ecdsa::SigningKey { private_key: key });
    let vk = no_way_jose_graviola::ecdsa::es384::verifying_key_from_x962(&pub_bytes).unwrap();

    let sk_jwk = sk.to_jwk();
    assert_eq!(sk_jwk.alg.as_deref(), Some("ES384"));
    match &sk_jwk.key {
        JwkParams::Ec(p) => assert_eq!(p.crv, EcCurve::P384),
        _ => panic!("expected EC params"),
    }

    let sk2: no_way_jose_core::SigningKey<no_way_jose_graviola::ecdsa::Es384> =
        FromJwk::from_jwk(&sk_jwk).unwrap();
    let vk2: no_way_jose_core::VerifyingKey<no_way_jose_graviola::ecdsa::Es384> =
        FromJwk::from_jwk(&vk.to_jwk()).unwrap();

    let token = UnsignedToken::<no_way_jose_graviola::ecdsa::Es384, _>::new(test_claims())
        .sign(&sk2)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::ecdsa::Es384, Claims> =
        token.to_string().parse().unwrap();
    parsed.verify(&vk2, &no_validation()).unwrap();
}

#[test]
fn graviola_eddsa_jwk_roundtrip() {
    let sk = no_way_jose_graviola::eddsa::signing_key_from_bytes(&[7u8; 32]).unwrap();
    let vk = no_way_jose_graviola::eddsa::verifying_key_from_signing(&sk);

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

    let sk2: no_way_jose_graviola::eddsa::SigningKey = FromJwk::from_jwk(&sk_jwk).unwrap();
    let vk2: no_way_jose_graviola::eddsa::VerifyingKey = FromJwk::from_jwk(&vk_jwk).unwrap();

    let token = UnsignedToken::<no_way_jose_graviola::eddsa::EdDsa, _>::new(test_claims())
        .sign(&sk2)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::eddsa::EdDsa, Claims> =
        token.to_string().parse().unwrap();
    parsed.verify(&vk2, &no_validation()).unwrap();
}

#[test]
fn graviola_hmac_jwk_roundtrip() {
    let key_bytes = b"super-secret-key-for-testing-256".to_vec();
    let sk = no_way_jose_graviola::hmac::symmetric_key(key_bytes).unwrap();

    let jwk = sk.to_jwk();
    assert_eq!(jwk.kty(), "oct");
    assert_eq!(jwk.alg.as_deref(), Some("HS256"));

    let sk2: no_way_jose_graviola::hmac::SigningKey = FromJwk::from_jwk(&jwk).unwrap();
    let vk2: no_way_jose_graviola::hmac::VerifyingKey = FromJwk::from_jwk(&jwk).unwrap();

    let token = UnsignedToken::<no_way_jose_graviola::hmac::Hs256, _>::new(test_claims())
        .sign(&sk2)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_graviola::hmac::Hs256, Claims> =
        token.to_string().parse().unwrap();
    parsed.verify(&vk2, &no_validation()).unwrap();
}

#[test]
fn graviola_ecdsa_jwk_interop_with_rustcrypto() {
    use graviola::signing::ecdsa;

    let key = graviola::key_agreement::p256::StaticPrivateKey::new_random().unwrap();
    let sk: no_way_jose_graviola::ecdsa::SigningKey =
        no_way_jose_core::key::Key::new(ecdsa::SigningKey { private_key: key });
    let sk_jwk = sk.to_jwk();

    let rc_vk: no_way_jose_ecdsa::VerifyingKey = FromJwk::from_jwk(&sk_jwk).unwrap();

    let token = UnsignedToken::<no_way_jose_graviola::ecdsa::Es256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256, Claims> =
        token.to_string().parse().unwrap();
    parsed.verify(&rc_vk, &no_validation()).unwrap();
}

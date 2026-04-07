use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{self, EcdsaKeyPair, KeyPair};
use no_way_jose_core::UnsignedToken;
use no_way_jose_core::error::JsonError;
use no_way_jose_core::json::{FromJson, JsonReader, JsonWriter, RawJson, ToJson};
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
        sub: "aws-lc".into(),
        admin: true,
    }
}

// ====================================================================
// HMAC
// ====================================================================

#[test]
fn aws_lc_hs256_roundtrip() {
    let key =
        no_way_jose_aws_lc::hmac::symmetric_key(b"super-secret-key-for-testing-256".to_vec())
            .unwrap();
    let vk =
        no_way_jose_aws_lc::hmac::verifying_key(b"super-secret-key-for-testing-256".to_vec())
            .unwrap();

    let compact = UnsignedToken::<no_way_jose_aws_lc::hmac::Hs256, _>::new(test_claims())
        .sign(&key)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::hmac::Hs256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
    assert!(verified.claims.admin);
}

#[test]
fn aws_lc_hs384_roundtrip() {
    let key = no_way_jose_aws_lc::hmac::hs384::symmetric_key(vec![0xABu8; 48]).unwrap();
    let vk = no_way_jose_aws_lc::hmac::hs384::verifying_key(vec![0xABu8; 48]).unwrap();

    let compact = UnsignedToken::<no_way_jose_aws_lc::hmac::Hs384, _>::new(test_claims())
        .sign(&key)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::hmac::Hs384, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_hs512_roundtrip() {
    let key = no_way_jose_aws_lc::hmac::hs512::symmetric_key(vec![0xCDu8; 64]).unwrap();
    let vk = no_way_jose_aws_lc::hmac::hs512::verifying_key(vec![0xCDu8; 64]).unwrap();

    let compact = UnsignedToken::<no_way_jose_aws_lc::hmac::Hs512, _>::new(test_claims())
        .sign(&key)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::hmac::Hs512, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_hs256_interop_with_rustcrypto() {
    let key_bytes = b"super-secret-key-for-testing-256".to_vec();

    let aws_key = no_way_jose_aws_lc::hmac::symmetric_key(key_bytes.clone()).unwrap();
    let compact = UnsignedToken::<no_way_jose_aws_lc::hmac::Hs256, _>::new(test_claims())
        .sign(&aws_key)
        .unwrap();

    let rc_vk = no_way_jose_hmac::verifying_key(key_bytes).unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_hmac::Hs256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&rc_vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

// ====================================================================
// EdDSA
// ====================================================================

#[test]
fn aws_lc_eddsa_roundtrip() {
    let sk = no_way_jose_aws_lc::eddsa::signing_key_from_seed(&[42u8; 32]).unwrap();
    let vk = no_way_jose_aws_lc::eddsa::verifying_key_from_signing(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::eddsa::EdDsa, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::eddsa::EdDsa, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_eddsa_interop_sign_awslc_verify_rc() {
    let seed = [42u8; 32];

    let aws_sk = no_way_jose_aws_lc::eddsa::signing_key_from_seed(&seed).unwrap();
    let compact = UnsignedToken::<no_way_jose_aws_lc::eddsa::EdDsa, _>::new(test_claims())
        .sign(&aws_sk)
        .unwrap();

    let rc_sk = no_way_jose_eddsa::signing_key_from_bytes(&seed);
    let rc_vk = no_way_jose_eddsa::verifying_key_from_signing(&rc_sk);
    let parsed: no_way_jose_core::CompactJws<no_way_jose_eddsa::EdDsa, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&rc_vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_eddsa_interop_sign_rc_verify_awslc() {
    let seed = [42u8; 32];

    let rc_sk = no_way_jose_eddsa::signing_key_from_bytes(&seed);
    let compact = UnsignedToken::<no_way_jose_eddsa::EdDsa, _>::new(test_claims())
        .sign(&rc_sk)
        .unwrap();

    let aws_vk = no_way_jose_aws_lc::eddsa::verifying_key_from_signing(
        &no_way_jose_aws_lc::eddsa::signing_key_from_seed(&seed).unwrap(),
    );
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::eddsa::EdDsa, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&aws_vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

// ====================================================================
// ECDSA
// ====================================================================

#[test]
fn aws_lc_es256_roundtrip() {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let sk = no_way_jose_aws_lc::ecdsa::signing_key_from_pkcs8_der(pkcs8.as_ref()).unwrap();
    let vk = no_way_jose_aws_lc::ecdsa::verifying_key_from_signing(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::ecdsa::Es256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::ecdsa::Es256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_es384_roundtrip() {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &rng).unwrap();
    let sk = no_way_jose_aws_lc::ecdsa::es384::signing_key_from_pkcs8_der(pkcs8.as_ref()).unwrap();
    let vk = no_way_jose_aws_lc::ecdsa::es384::verifying_key_from_signing(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::ecdsa::Es384, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::ecdsa::Es384, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_es512_roundtrip() {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P521_SHA512_FIXED_SIGNING, &rng).unwrap();
    let sk = no_way_jose_aws_lc::ecdsa::es512::signing_key_from_pkcs8_der(pkcs8.as_ref()).unwrap();
    let vk = no_way_jose_aws_lc::ecdsa::es512::verifying_key_from_signing(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::ecdsa::Es512, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::ecdsa::Es512, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_es256_interop_sign_awslc_verify_rc() {
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let aws_sk =
        no_way_jose_aws_lc::ecdsa::signing_key_from_pkcs8_der(pkcs8.as_ref()).unwrap();
    let pub_bytes = aws_sk.inner().public_key().as_ref();

    let compact = UnsignedToken::<no_way_jose_aws_lc::ecdsa::Es256, _>::new(test_claims())
        .sign(&aws_sk)
        .unwrap();

    let rc_vk = no_way_jose_ecdsa::verifying_key_from_sec1(pub_bytes).unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_ecdsa::Es256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&rc_vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

// ====================================================================
// RSA
// ====================================================================

fn generate_rsa_key() -> aws_lc_rs::signature::RsaKeyPair {
    aws_lc_rs::signature::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap()
}

fn rsa_vk_from_sk<A: no_way_jose_core::key::HasKey<no_way_jose_core::key::Signing, Key = aws_lc_rs::signature::RsaKeyPair> + no_way_jose_core::key::HasKey<no_way_jose_core::key::Verifying, Key = no_way_jose_aws_lc::rsa::RsaVerifyingKey>>(
    sk: &no_way_jose_core::SigningKey<A>,
) -> no_way_jose_core::VerifyingKey<A> {
    no_way_jose_core::key::Key::new(no_way_jose_aws_lc::rsa::RsaVerifyingKey::from_der(
        sk.inner().public_key().as_ref(),
    ))
}

#[test]
fn aws_lc_rs256_roundtrip() {
    let sk: no_way_jose_aws_lc::rsa::SigningKey =
        no_way_jose_core::key::Key::new(generate_rsa_key());
    let vk = rsa_vk_from_sk(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::rsa::Rs256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Rs256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_ps256_roundtrip() {
    let sk: no_way_jose_aws_lc::rsa::ps256::SigningKey =
        no_way_jose_core::key::Key::new(generate_rsa_key());
    let vk = rsa_vk_from_sk(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::rsa::Ps256, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Ps256, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_rs384_roundtrip() {
    let sk: no_way_jose_aws_lc::rsa::rs384::SigningKey =
        no_way_jose_core::key::Key::new(generate_rsa_key());
    let vk = rsa_vk_from_sk(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::rsa::Rs384, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Rs384, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_ps384_roundtrip() {
    let sk: no_way_jose_aws_lc::rsa::ps384::SigningKey =
        no_way_jose_core::key::Key::new(generate_rsa_key());
    let vk = rsa_vk_from_sk(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::rsa::Ps384, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Ps384, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_rs512_roundtrip() {
    let sk: no_way_jose_aws_lc::rsa::rs512::SigningKey =
        no_way_jose_core::key::Key::new(generate_rsa_key());
    let vk = rsa_vk_from_sk(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::rsa::Rs512, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Rs512, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_ps512_roundtrip() {
    let sk: no_way_jose_aws_lc::rsa::ps512::SigningKey =
        no_way_jose_core::key::Key::new(generate_rsa_key());
    let vk = rsa_vk_from_sk(&sk);

    let compact = UnsignedToken::<no_way_jose_aws_lc::rsa::Ps512, _>::new(test_claims())
        .sign(&sk)
        .unwrap();
    let parsed: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Ps512, Claims> =
        compact.to_string().parse().unwrap();
    let verified = parsed.verify(&vk, &no_validation()).unwrap();
    assert_eq!(verified.claims.sub, "aws-lc");
}

// ====================================================================
// AES-GCM (via dir)
// ====================================================================

#[test]
fn aws_lc_dir_a256gcm_roundtrip() {
    use no_way_jose_core::dir;
    use no_way_jose_core::purpose::Encrypted;
    use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};

    let key = vec![0x42u8; 32];
    let enc_key = dir::encryption_key(key.clone());
    let dec_key = dir::decryption_key(key);

    let token =
        UnsealedToken::<Encrypted<dir::Dir, no_way_jose_aws_lc::aes_gcm::A256Gcm>, Claims>::new(
            test_claims(),
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, no_way_jose_aws_lc::aes_gcm::A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();
    assert_eq!(unsealed.claims.sub, "aws-lc");
    assert!(unsealed.claims.admin);
}

#[test]
fn aws_lc_dir_a128gcm_roundtrip() {
    use no_way_jose_core::dir;
    use no_way_jose_core::purpose::Encrypted;
    use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};

    let key = vec![0x42u8; 16];
    let enc_key = dir::encryption_key(key.clone());
    let dec_key = dir::decryption_key(key);

    let token =
        UnsealedToken::<Encrypted<dir::Dir, no_way_jose_aws_lc::aes_gcm::A128Gcm>, Claims>::new(
            test_claims(),
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, no_way_jose_aws_lc::aes_gcm::A128Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();
    assert_eq!(unsealed.claims.sub, "aws-lc");
}

#[test]
fn aws_lc_aes_gcm_interop_encrypt_awslc_decrypt_rc() {
    use no_way_jose_core::dir;
    use no_way_jose_core::purpose::Encrypted;
    use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};

    let key = vec![0x42u8; 32];
    let enc_key = dir::encryption_key(key.clone());
    let dec_key = dir::decryption_key(key);

    let token =
        UnsealedToken::<Encrypted<dir::Dir, no_way_jose_aws_lc::aes_gcm::A256Gcm>, Claims>::new(
            test_claims(),
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, no_way_jose_aes_gcm::A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();
    assert_eq!(unsealed.claims.sub, "aws-lc");
}

// ====================================================================
// RFC test vector verification with aws-lc-rs backend
// ====================================================================

const ES256_JWK_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

const ES256_TOKEN: &str = "\
    eyJhbGciOiJFUzI1NiJ9.\
    eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt\
    cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
    DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA\
    pmWQxfKTUJqPP3-Kg6NU1Q";

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

const EDDSA_TOKEN: &str = "\
    eyJhbGciOiJFZERTQSJ9.\
    RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
    hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

const RFC7520_HS256_TOKEN: &str = "\
    eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9.\
    SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH\
    lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk\
    b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm\
    UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4.\
    s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

/// DER-encode an RSA public key (PKCS#1 RSAPublicKey format) from raw n and e bytes.
fn der_encode_rsa_pubkey(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn encode_integer(bytes: &[u8]) -> Vec<u8> {
        let needs_pad = bytes[0] & 0x80 != 0;
        let len = bytes.len() + usize::from(needs_pad);
        let mut out = vec![0x02];
        der_encode_length(&mut out, len);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(bytes);
        out
    }

    fn der_encode_length(out: &mut Vec<u8>, len: usize) {
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.extend_from_slice(&[0x81, len as u8]);
        } else {
            out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
        }
    }

    let n_enc = encode_integer(n);
    let e_enc = encode_integer(e);
    let seq_len = n_enc.len() + e_enc.len();
    let mut out = vec![0x30];
    der_encode_length(&mut out, seq_len);
    out.extend_from_slice(&n_enc);
    out.extend_from_slice(&e_enc);
    out
}

fn rfc7515_a2_rsa_public_key_der() -> Vec<u8> {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let n = Base64UrlUnpadded::decode_vec(
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\
         HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\
         D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\
         SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\
         MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\
         NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    )
    .unwrap();
    let e = Base64UrlUnpadded::decode_vec("AQAB").unwrap();
    der_encode_rsa_pubkey(&n, &e)
}

#[test]
fn aws_lc_es256_verify_rfc7515_a3() {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let d_bytes = Base64UrlUnpadded::decode_vec(ES256_JWK_D).unwrap();
    let rc_sk = p256::ecdsa::SigningKey::from_slice(&d_bytes).unwrap();
    let rc_vk = p256::ecdsa::VerifyingKey::from(&rc_sk);
    let pub_bytes = rc_vk.to_sec1_point(false);

    let vk =
        no_way_jose_aws_lc::ecdsa::verifying_key_from_public_bytes(pub_bytes.as_bytes()).unwrap();

    let token: no_way_jose_core::CompactJws<no_way_jose_aws_lc::ecdsa::Es256, RawJson> =
        ES256_TOKEN.parse().unwrap();
    let _unsealed = token.verify(&vk, &no_validation()).unwrap();
}

#[test]
fn aws_lc_rs256_verify_rfc7515_a2() {
    let pk_der = rfc7515_a2_rsa_public_key_der();
    let vk = no_way_jose_aws_lc::rsa::verifying_key_from_der(&pk_der);

    let token: no_way_jose_core::CompactJws<no_way_jose_aws_lc::rsa::Rs256, RawJson> =
        RS256_TOKEN.parse().unwrap();
    let _unsealed = token.verify(&vk, &no_validation()).unwrap();
}

#[test]
fn aws_lc_eddsa_verify_rfc8037() {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let d_bytes =
        Base64UrlUnpadded::decode_vec("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A").unwrap();
    let sk = no_way_jose_aws_lc::eddsa::signing_key_from_seed(&d_bytes).unwrap();
    let vk = no_way_jose_aws_lc::eddsa::verifying_key_from_signing(&sk);

    let token: no_way_jose_core::CompactJws<no_way_jose_aws_lc::eddsa::EdDsa, RawJson> =
        EDDSA_TOKEN.parse().unwrap();
    let _unsealed = token.verify(&vk, &no_validation()).unwrap();
}

#[test]
fn aws_lc_rfc7520_hs256_verify() {
    use base64ct::{Base64UrlUnpadded, Encoding};

    let key_bytes =
        Base64UrlUnpadded::decode_vec("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg").unwrap();
    let vk = no_way_jose_aws_lc::hmac::verifying_key(key_bytes).unwrap();

    let token: no_way_jose_core::CompactJws<no_way_jose_aws_lc::hmac::Hs256, RawJson> =
        RFC7520_HS256_TOKEN.parse().unwrap();
    let _unsealed = token.verify(&vk, &no_validation()).unwrap();
}

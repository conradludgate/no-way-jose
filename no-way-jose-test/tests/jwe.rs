use base64ct::{Base64UrlUnpadded, Encoding};
use no_way_jose_aes_cbc_hs::{A128CbcHs256, A256CbcHs512};
use no_way_jose_aes_gcm::{A128Gcm, A256Gcm};
use no_way_jose_core::JoseError;
use no_way_jose_core::dir;
use no_way_jose_core::json::{FromJson, JsonReader, JsonWriter, RawJson, ToJson};
use no_way_jose_core::purpose::Encrypted;
use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
use no_way_jose_core::validation::NoValidation;
use no_way_jose_pbes2::Pbes2Hs512A256Kw;
use no_way_jose_rsa::{RsaOaep, RsaOaep256};

#[derive(Debug, PartialEq)]
struct Claims {
    sub: String,
    admin: bool,
}

impl ToJson for Claims {
    fn write_json(&self, buf: &mut Vec<u8>) {
        let mut w = JsonWriter::new();
        w.string("sub", &self.sub);
        w.bool("admin", self.admin);
        buf.extend_from_slice(&w.finish());
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
            sub: sub.ok_or(JoseError::InvalidToken("missing sub"))?,
            admin: admin.ok_or(JoseError::InvalidToken("missing admin"))?,
        })
    }
}

fn test_key() -> Vec<u8> {
    vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ]
}

type DirA256Gcm = CompactJwe<dir::Dir, A256Gcm, Claims>;

fn no_validation<T>() -> NoValidation<T> {
    NoValidation::dangerous_no_validation()
}

#[test]
fn dir_a256gcm_roundtrip() {
    let key_bytes = test_key();
    let enc_key = dir::encryption_key(key_bytes.clone());
    let dec_key = dir::decryption_key(key_bytes);

    let claims = Claims {
        sub: "1234567890".into(),
        admin: true,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let unsealed = compact.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "1234567890");
    assert!(unsealed.claims.admin);
}

#[test]
fn dir_a256gcm_wrong_key_fails() {
    let enc_key = dir::encryption_key(test_key());
    let wrong_key = dir::decryption_key(vec![0xff; 32]);

    let claims = Claims {
        sub: "test".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_key, &no_validation());

    assert!(result.is_err());
}

#[test]
fn dir_a256gcm_tampered_ciphertext_fails() {
    let key_bytes = test_key();
    let enc_key = dir::encryption_key(key_bytes.clone());
    let dec_key = dir::decryption_key(key_bytes);

    let claims = Claims {
        sub: "tamper".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let mut parts: Vec<&str> = serialized.splitn(5, '.').collect();
    let tampered_ct = format!("{}AA", parts[3]);
    parts[3] = &tampered_ct;
    let tampered = parts.join(".");

    let parsed: DirA256Gcm = tampered.parse().unwrap();
    let result = parsed.decrypt(&dec_key, &no_validation());
    assert!(result.is_err());
}

#[test]
fn dir_a256gcm_token_display_parse_roundtrip() {
    let key_bytes = test_key();
    let enc_key = dir::encryption_key(key_bytes.clone());
    let dec_key = dir::decryption_key(key_bytes);

    let claims = Claims {
        sub: "roundtrip".into(),
        admin: true,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    assert_eq!(serialized.matches('.').count(), 4);

    let parsed: DirA256Gcm = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "roundtrip");
    assert!(unsealed.claims.admin);
}

#[test]
fn dir_a256gcm_raw_json_roundtrip() {
    let key_bytes = test_key();
    let enc_key = dir::encryption_key(key_bytes.clone());
    let dec_key = dir::decryption_key(key_bytes);

    let raw = RawJson(b"{\"hello\":\"world\"}".to_vec());

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, RawJson>::new(raw);
    let compact = token.encrypt(&enc_key).unwrap();
    let unsealed: UnsealedToken<_, _> = compact.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.0, b"{\"hello\":\"world\"}");
}

#[test]
fn dir_a256gcm_header_has_alg_and_enc() {
    let key_bytes = test_key();
    let enc_key = dir::encryption_key(key_bytes);

    let claims = Claims {
        sub: "hdr".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "dir");
    assert_eq!(header.enc.as_deref(), Some("A256GCM"));
}

#[test]
fn dir_rejects_nonempty_encrypted_key() {
    let key_bytes = test_key();
    let enc_key = dir::encryption_key(key_bytes.clone());
    let dec_key = dir::decryption_key(key_bytes);

    let claims = Claims {
        sub: "ek".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let parts: Vec<&str> = serialized.splitn(5, '.').collect();
    let tampered = format!("{}.AAAA.{}.{}.{}", parts[0], parts[2], parts[3], parts[4]);

    let parsed: DirA256Gcm = tampered.parse().unwrap();
    let result = parsed.decrypt(&dec_key, &no_validation());
    assert!(result.is_err());
}

#[test]
fn dir_rejects_wrong_key_length() {
    let short_key = vec![0u8; 16];
    let enc_key = dir::encryption_key(short_key);

    let claims = Claims {
        sub: "short".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256Gcm>, Claims>::new(claims);
    let result = token.encrypt(&enc_key);
    assert!(result.is_err());
}

// ====================================================================
// AES Key Wrap tests
// ====================================================================

/// RFC 7520 Section 5.8 — A128KW + A128GCM compact token.
/// Whitespace removed from the RFC representation.
const RFC7520_A128KW_A128GCM_TOKEN: &str = "\
eyJhbGciOiJBMTI4S1ciLCJraWQiOiI4MWIyMDk2NS04MzMyLTQzZDktYTQ2OC\
04MjE2MGFkOTFhYzgiLCJlbmMiOiJBMTI4R0NNIn0\
.\
CBI6oDw8MydIx1IBntf_lQcw2MmJKIQx\
.\
Qx0pmsDa8KnJc9Jo\
.\
AwliP-KmWgsZ37BvzCefNen6VTbRK3QMA4TkvRkH0tP1bTdhtFJgJxeVmJkLD6\
1A1hnWGetdg11c9ADsnWgL56NyxwSYjU1ZEHcGkd3EkU0vjHi9gTlb90qSYFfe\
F0LwkcTtjbYKCsiNJQkcIp1yeM03OmuiYSoYJVSpf7ej6zaYcMv3WwdxDFl8RE\
wOhNImk2Xld2JXq6BR53TSFkyT7PwVLuq-1GwtGHlQeg7gDT6xW0JqHDPn_H-p\
uQsmthc9Zg0ojmJfqqFvETUxLAF-KjcBTS5dNy6egwkYtOt8EIHK-oEsKYtZRa\
a8Z7MOZ7UGxGIMvEmxrGCPeJa14slv2-gaqK0kEThkaSqdYw0FkQZF\
.\
ER7MWJZ1FBI_NKvn7Zb1Lw";

/// RFC 7520 Figure 72 plaintext (Tolkien quote with EN DASH U+2013).
fn rfc7520_plaintext() -> Vec<u8> {
    let s = "You can trust us to stick with you through thick and \
             thin\u{2013}to the bitter end. And you can trust us to \
             keep any secret of yours\u{2013}closer than you keep it \
             yourself. But you cannot trust us to let you face trouble \
             alone, and go off without a word. We are your friends, Frodo.";
    s.into()
}

#[test]
fn rfc7520_a128kw_a128gcm_decrypt() {
    let kek_bytes = Base64UrlUnpadded::decode_vec("GZy6sIZ6wl9NJOKB-jnmVQ").unwrap();
    let dec_key = no_way_jose_aes_kw::a128kw::decryption_key(kek_bytes).unwrap();

    let token: CompactJwe<no_way_jose_aes_kw::A128Kw, A128Gcm, RawJson> =
        RFC7520_A128KW_A128GCM_TOKEN.parse().unwrap();
    let unsealed = token.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.0, rfc7520_plaintext());
}

#[test]
fn a128kw_a128gcm_roundtrip() {
    let kek = vec![0x42u8; 16];
    let enc_key = no_way_jose_aes_kw::a128kw::encryption_key(kek.clone()).unwrap();
    let dec_key = no_way_jose_aes_kw::a128kw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "a128kw".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_kw::A128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    assert_eq!(serialized.matches('.').count(), 4);

    let parsed: CompactJwe<no_way_jose_aes_kw::A128Kw, A128Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "a128kw");
    assert!(unsealed.claims.admin);
}

#[test]
fn a256kw_a256gcm_roundtrip() {
    let kek = vec![0x77u8; 32];
    let enc_key = no_way_jose_aes_kw::a256kw::encryption_key(kek.clone()).unwrap();
    let dec_key = no_way_jose_aes_kw::a256kw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "a256kw".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_kw::A256Kw, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let parsed: CompactJwe<no_way_jose_aes_kw::A256Kw, A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "a256kw");
    assert!(!unsealed.claims.admin);
}

#[test]
fn a128kw_wrong_kek_fails() {
    let enc_key = no_way_jose_aes_kw::a128kw::encryption_key(vec![0x42u8; 16]).unwrap();
    let wrong_key = no_way_jose_aes_kw::a128kw::decryption_key(vec![0xffu8; 16]).unwrap();

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_kw::A128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_key, &no_validation());

    assert!(result.is_err());
}

#[test]
fn a128kw_rejects_wrong_kek_length() {
    let result = no_way_jose_aes_kw::a128kw::encryption_key(vec![0u8; 15]);
    assert!(result.is_err());
}

#[test]
fn a256kw_rejects_wrong_kek_length() {
    let result = no_way_jose_aes_kw::a256kw::encryption_key(vec![0u8; 31]);
    assert!(result.is_err());
}

#[test]
fn a128kw_header_has_alg_and_enc() {
    let enc_key = no_way_jose_aes_kw::a128kw::encryption_key(vec![0x42u8; 16]).unwrap();

    let claims = Claims {
        sub: "hdr".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_kw::A128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "A128KW");
    assert_eq!(header.enc.as_deref(), Some("A128GCM"));
}

// ====================================================================
// AES-CBC-HS tests
// ====================================================================

#[test]
fn dir_a128cbc_hs256_roundtrip() {
    let key = vec![0x42u8; 32];
    let enc_key = dir::encryption_key(key.clone());
    let dec_key = dir::decryption_key(key);

    let claims = Claims {
        sub: "cbc-hs".into(),
        admin: true,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A128CbcHs256>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, A128CbcHs256, Claims> = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "cbc-hs");
    assert!(unsealed.claims.admin);
}

#[test]
fn dir_a256cbc_hs512_roundtrip() {
    let key = vec![0x77u8; 64];
    let enc_key = dir::encryption_key(key.clone());
    let dec_key = dir::decryption_key(key);

    let claims = Claims {
        sub: "cbc512".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A256CbcHs512>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<dir::Dir, A256CbcHs512, Claims> = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "cbc512");
    assert!(!unsealed.claims.admin);
}

#[test]
fn a128cbc_hs256_wrong_key_fails() {
    let enc_key = dir::encryption_key(vec![0x42u8; 32]);
    let wrong_key = dir::decryption_key(vec![0xffu8; 32]);

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A128CbcHs256>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_key, &no_validation());
    assert!(result.is_err());
}

#[test]
fn a128cbc_hs256_tampered_ciphertext_fails() {
    let key = vec![0x42u8; 32];
    let enc_key = dir::encryption_key(key.clone());
    let dec_key = dir::decryption_key(key);

    let claims = Claims {
        sub: "tamper".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<dir::Dir, A128CbcHs256>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let parts: Vec<&str> = serialized.splitn(5, '.').collect();
    let mut ct_bytes = Base64UrlUnpadded::decode_vec(parts[3]).unwrap();
    ct_bytes[0] ^= 0xff;
    let tampered_ct = Base64UrlUnpadded::encode_string(&ct_bytes);
    let tampered = format!(
        "{}.{}.{}.{}.{}",
        parts[0], parts[1], parts[2], tampered_ct, parts[4]
    );

    let parsed: CompactJwe<dir::Dir, A128CbcHs256, Claims> = tampered.parse().unwrap();
    let result = parsed.decrypt(&dec_key, &no_validation());
    assert!(result.is_err());
}

#[test]
fn a128kw_a128cbc_hs256_roundtrip() {
    let kek = vec![0x42u8; 16];
    let enc_key = no_way_jose_aes_kw::a128kw::encryption_key(kek.clone()).unwrap();
    let dec_key = no_way_jose_aes_kw::a128kw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "kw-cbc".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_kw::A128Kw, A128CbcHs256>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let parsed: CompactJwe<no_way_jose_aes_kw::A128Kw, A128CbcHs256, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "kw-cbc");
    assert!(unsealed.claims.admin);
}

// ====================================================================
// RSA key management tests
// ====================================================================

fn test_rsa_keypair() -> (rsa::RsaPublicKey, rsa::RsaPrivateKey) {
    use rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);
    (public_key, private_key)
}

#[test]
fn rsa_oaep_a256gcm_roundtrip() {
    let (pub_key, priv_key) = test_rsa_keypair();
    let enc_key = no_way_jose_rsa::rsa_oaep::encryption_key(pub_key);
    let dec_key = no_way_jose_rsa::rsa_oaep::decryption_key(priv_key);

    let claims = Claims {
        sub: "rsa-oaep".into(),
        admin: true,
    };

    let token = UnsealedToken::<Encrypted<RsaOaep, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<RsaOaep, A256Gcm, Claims> = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "rsa-oaep");
    assert!(unsealed.claims.admin);
}

#[test]
fn rsa_oaep256_a128gcm_roundtrip() {
    let (pub_key, priv_key) = test_rsa_keypair();
    let enc_key = no_way_jose_rsa::rsa_oaep_256::encryption_key(pub_key);
    let dec_key = no_way_jose_rsa::rsa_oaep_256::decryption_key(priv_key);

    let claims = Claims {
        sub: "rsa-oaep-256".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<RsaOaep256, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<RsaOaep256, A128Gcm, Claims> = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "rsa-oaep-256");
    assert!(!unsealed.claims.admin);
}

#[test]
fn rsa_oaep_wrong_key_fails() {
    let (pub_key, _) = test_rsa_keypair();
    let (_, wrong_priv) = test_rsa_keypair();
    let enc_key = no_way_jose_rsa::rsa_oaep::encryption_key(pub_key);
    let wrong_dec = no_way_jose_rsa::rsa_oaep::decryption_key(wrong_priv);

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<RsaOaep, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_dec, &no_validation());
    assert!(result.is_err());
}

#[test]
fn rsa_oaep_header_correct() {
    let (pub_key, _) = test_rsa_keypair();
    let enc_key = no_way_jose_rsa::rsa_oaep::encryption_key(pub_key);

    let claims = Claims {
        sub: "hdr".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<RsaOaep, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "RSA-OAEP");
    assert_eq!(header.enc.as_deref(), Some("A256GCM"));
}

#[test]
fn rsa1_5_a128cbc_hs256_roundtrip() {
    let (pub_key, priv_key) = test_rsa_keypair();
    let enc_key = no_way_jose_rsa::rsa1_5::encryption_key(pub_key);
    let dec_key = no_way_jose_rsa::rsa1_5::decryption_key(priv_key);

    let claims = Claims {
        sub: "rsa15".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_rsa::Rsa1_5, A128CbcHs256>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<no_way_jose_rsa::Rsa1_5, A128CbcHs256, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "rsa15");
    assert!(unsealed.claims.admin);
}

// ====================================================================
// AES-GCM key wrapping tests
// ====================================================================

#[test]
fn a128gcmkw_a128gcm_roundtrip() {
    let kek = vec![0x42u8; 16];
    let enc_key = no_way_jose_aes_gcm_kw::a128gcmkw::encryption_key(kek.clone()).unwrap();
    let dec_key = no_way_jose_aes_gcm_kw::a128gcmkw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "gcmkw128".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "A128GCMKW");
    assert_eq!(header.enc.as_deref(), Some("A128GCM"));

    let serialized = compact.to_string();
    let parsed: CompactJwe<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "gcmkw128");
    assert!(unsealed.claims.admin);
}

#[test]
fn a256gcmkw_a256gcm_roundtrip() {
    let kek = vec![0x77u8; 32];
    let enc_key = no_way_jose_aes_gcm_kw::a256gcmkw::encryption_key(kek.clone()).unwrap();
    let dec_key = no_way_jose_aes_gcm_kw::a256gcmkw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "gcmkw256".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_gcm_kw::A256GcmKw, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<no_way_jose_aes_gcm_kw::A256GcmKw, A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "gcmkw256");
    assert!(!unsealed.claims.admin);
}

#[test]
fn a128gcmkw_wrong_kek_fails() {
    let enc_key = no_way_jose_aes_gcm_kw::a128gcmkw::encryption_key(vec![0x42u8; 16]).unwrap();
    let wrong = no_way_jose_aes_gcm_kw::a128gcmkw::decryption_key(vec![0xffu8; 16]).unwrap();

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong, &no_validation());
    assert!(result.is_err());
}

#[test]
fn a128gcmkw_header_contains_iv_and_tag() {
    let kek = vec![0x42u8; 16];
    let enc_key = no_way_jose_aes_gcm_kw::a128gcmkw::encryption_key(kek).unwrap();

    let claims = Claims {
        sub: "ivtag".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_aes_gcm_kw::A128GcmKw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let header_b64 = serialized.split('.').next().unwrap();
    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64).unwrap();
    let header_str = core::str::from_utf8(&header_bytes).unwrap();
    assert!(header_str.contains("\"iv\""));
    assert!(header_str.contains("\"tag\""));
}

// ====================================================================
// ECDH-ES tests
// ====================================================================

fn test_p256_keypair() -> (
    no_way_jose_ecdh_es::EcPublicKey,
    no_way_jose_ecdh_es::EcPrivateKey,
) {
    let secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let public = secret.public_key();
    (
        no_way_jose_ecdh_es::EcPublicKey::P256(public),
        no_way_jose_ecdh_es::EcPrivateKey::P256(secret),
    )
}

#[test]
fn ecdh_es_a128kw_a128gcm_roundtrip() {
    let (pub_key, priv_key) = test_p256_keypair();
    let enc_key = no_way_jose_ecdh_es::ecdh_es_a128kw::encryption_key(pub_key);
    let dec_key = no_way_jose_ecdh_es::ecdh_es_a128kw::decryption_key(priv_key);

    let claims = Claims {
        sub: "ecdh-kw".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_ecdh_es::EcdhEsA128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "ECDH-ES+A128KW");
    assert_eq!(header.enc.as_deref(), Some("A128GCM"));

    let serialized = compact.to_string();
    let parsed: CompactJwe<no_way_jose_ecdh_es::EcdhEsA128Kw, A128Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "ecdh-kw");
    assert!(unsealed.claims.admin);
}

#[test]
fn ecdh_es_direct_a256gcm_roundtrip() {
    let (pub_key, priv_key) = test_p256_keypair();
    let enc_key = no_way_jose_ecdh_es::ecdh_es::encryption_key(pub_key);
    let dec_key = no_way_jose_ecdh_es::ecdh_es::decryption_key(priv_key);

    let claims = Claims {
        sub: "ecdh-direct".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_ecdh_es::EcdhEs, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "ECDH-ES");

    let serialized = compact.to_string();
    let parsed: CompactJwe<no_way_jose_ecdh_es::EcdhEs, A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "ecdh-direct");
    assert!(!unsealed.claims.admin);
}

#[test]
fn ecdh_es_wrong_key_fails() {
    let (pub_key, _) = test_p256_keypair();
    let (_, wrong_priv) = test_p256_keypair();
    let enc_key = no_way_jose_ecdh_es::ecdh_es_a128kw::encryption_key(pub_key);
    let wrong_dec = no_way_jose_ecdh_es::ecdh_es_a128kw::decryption_key(wrong_priv);

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_ecdh_es::EcdhEsA128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_dec, &no_validation());
    assert!(result.is_err());
}

#[test]
fn ecdh_es_header_contains_epk() {
    let (pub_key, _) = test_p256_keypair();
    let enc_key = no_way_jose_ecdh_es::ecdh_es_a128kw::encryption_key(pub_key);

    let claims = Claims {
        sub: "epk".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_ecdh_es::EcdhEsA128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let header_b64 = serialized.split('.').next().unwrap();
    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64).unwrap();
    let header_str = core::str::from_utf8(&header_bytes).unwrap();
    assert!(header_str.contains("\"epk\""));
    assert!(header_str.contains("\"P-256\""));
}

// ====================================================================
// PBES2 tests
// ====================================================================

#[test]
fn pbes2_hs256_a128kw_a128gcm_roundtrip() {
    let password = b"supersecretpassword";
    let enc_key = no_way_jose_pbes2::pbes2_hs256_a128kw::encryption_key(password.to_vec());
    let dec_key = no_way_jose_pbes2::pbes2_hs256_a128kw::decryption_key(password.to_vec());

    let claims = Claims {
        sub: "pbes2".into(),
        admin: true,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_pbes2::Pbes2Hs256A128Kw, A128Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "PBES2-HS256+A128KW");
    assert_eq!(header.enc.as_deref(), Some("A128GCM"));

    let serialized = compact.to_string();
    let parsed: CompactJwe<no_way_jose_pbes2::Pbes2Hs256A128Kw, A128Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "pbes2");
    assert!(unsealed.claims.admin);
}

#[test]
fn pbes2_hs512_a256kw_a256gcm_roundtrip() {
    let password = b"anotherpassword";
    let enc_key = no_way_jose_pbes2::pbes2_hs512_a256kw::encryption_key(password.to_vec());
    let dec_key = no_way_jose_pbes2::pbes2_hs512_a256kw::decryption_key(password.to_vec());

    let claims = Claims {
        sub: "pbes2-512".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_pbes2::Pbes2Hs512A256Kw, A256Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let serialized = compact.to_string();

    let parsed: CompactJwe<no_way_jose_pbes2::Pbes2Hs512A256Kw, A256Gcm, Claims> =
        serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "pbes2-512");
    assert!(!unsealed.claims.admin);
}

#[test]
fn pbes2_wrong_password_fails() {
    let enc_key = no_way_jose_pbes2::pbes2_hs256_a128kw::encryption_key(b"correct".to_vec());
    let wrong_dec = no_way_jose_pbes2::pbes2_hs256_a128kw::decryption_key(b"wrong".to_vec());

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_pbes2::Pbes2Hs256A128Kw, A128Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_dec, &no_validation());
    assert!(result.is_err());
}

#[test]
fn pbes2_header_contains_p2s_and_p2c() {
    let password = b"test";
    let enc_key = no_way_jose_pbes2::pbes2_hs256_a128kw::encryption_key(password.to_vec());

    let claims = Claims {
        sub: "hdr".into(),
        admin: false,
    };

    let token =
        UnsealedToken::<Encrypted<no_way_jose_pbes2::Pbes2Hs256A128Kw, A128Gcm>, Claims>::new(
            claims,
        );
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let header_b64 = serialized.split('.').next().unwrap();
    let header_bytes = Base64UrlUnpadded::decode_vec(header_b64).unwrap();
    let header_str = core::str::from_utf8(&header_bytes).unwrap();
    assert!(header_str.contains("\"p2s\""));
    assert!(header_str.contains("\"p2c\""));
}

// ====================================================================
// RFC 7520 test vectors
// ====================================================================

/// RFC 7520 Section 5.3 — PBES2-HS512+A256KW with A128CBC-HS256.
/// Password from Figure 96: "entrap_o–peter_long–credit_tun" (EN DASH U+2013).
const RFC7520_PBES2_TOKEN: &str = "\
eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3\
hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl\
bmMiOiJBMTI4Q0JDLUhTMjU2In0\
.\
d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g\
.\
VBiCzVHNoLiR3F4V82uoTQ\
.\
23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR\
sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l\
TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb\
6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL\
_SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd\
PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok\
AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-\
zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V\
3kobXZ77ulMwDs4p\
.\
0HlwodAhOCILG5SQ2LQ9dg";

#[test]
fn rfc7520_pbes2_hs512_a256kw_a128cbc_hs256_decrypt() {
    let password = "entrap_o\u{2013}peter_long\u{2013}credit_tun";
    let dec_key = no_way_jose_pbes2::pbes2_hs512_a256kw::decryption_key(password.as_bytes());

    let token: CompactJwe<Pbes2Hs512A256Kw, A128CbcHs256, RawJson> =
        RFC7520_PBES2_TOKEN.parse().unwrap();
    let unsealed = token.decrypt(&dec_key, &no_validation()).unwrap();

    let plaintext = core::str::from_utf8(&unsealed.claims.0).unwrap();
    assert!(plaintext.contains("\"keys\""));
    assert!(plaintext.contains("77c7e2b8-6e13-45cf-8672-617b5b45243a"));
}

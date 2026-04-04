use base64ct::{Base64UrlUnpadded, Encoding};
use jose_aes_gcm::{A128Gcm, A256Gcm};
use jose_aes_kw;
use jose_core::JoseError;
use jose_core::dir;
use jose_core::json::{FromJson, JsonReader, JsonWriter, RawJson, ToJson};
use jose_core::purpose::Encrypted;
use jose_core::tokens::{CompactJwe, UnsealedToken};
use jose_core::validation::NoValidation;

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
    let dec_key = jose_aes_kw::a128kw::decryption_key(kek_bytes).unwrap();

    let token: CompactJwe<jose_aes_kw::A128Kw, A128Gcm, RawJson> =
        RFC7520_A128KW_A128GCM_TOKEN.parse().unwrap();
    let unsealed = token.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.0, rfc7520_plaintext());
}

#[test]
fn a128kw_a128gcm_roundtrip() {
    let kek = vec![0x42u8; 16];
    let enc_key = jose_aes_kw::a128kw::encryption_key(kek.clone()).unwrap();
    let dec_key = jose_aes_kw::a128kw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "a128kw".into(),
        admin: true,
    };

    let token = UnsealedToken::<Encrypted<jose_aes_kw::A128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    assert_eq!(serialized.matches('.').count(), 4);

    let parsed: CompactJwe<jose_aes_kw::A128Kw, A128Gcm, Claims> = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "a128kw");
    assert!(unsealed.claims.admin);
}

#[test]
fn a256kw_a256gcm_roundtrip() {
    let kek = vec![0x77u8; 32];
    let enc_key = jose_aes_kw::a256kw::encryption_key(kek.clone()).unwrap();
    let dec_key = jose_aes_kw::a256kw::decryption_key(kek).unwrap();

    let claims = Claims {
        sub: "a256kw".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<jose_aes_kw::A256Kw, A256Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let serialized = compact.to_string();
    let parsed: CompactJwe<jose_aes_kw::A256Kw, A256Gcm, Claims> = serialized.parse().unwrap();
    let unsealed = parsed.decrypt(&dec_key, &no_validation()).unwrap();

    assert_eq!(unsealed.claims.sub, "a256kw");
    assert!(!unsealed.claims.admin);
}

#[test]
fn a128kw_wrong_kek_fails() {
    let enc_key = jose_aes_kw::a128kw::encryption_key(vec![0x42u8; 16]).unwrap();
    let wrong_key = jose_aes_kw::a128kw::decryption_key(vec![0xffu8; 16]).unwrap();

    let claims = Claims {
        sub: "wrong".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<jose_aes_kw::A128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();
    let result = compact.decrypt(&wrong_key, &no_validation());

    assert!(result.is_err());
}

#[test]
fn a128kw_rejects_wrong_kek_length() {
    let result = jose_aes_kw::a128kw::encryption_key(vec![0u8; 15]);
    assert!(result.is_err());
}

#[test]
fn a256kw_rejects_wrong_kek_length() {
    let result = jose_aes_kw::a256kw::encryption_key(vec![0u8; 31]);
    assert!(result.is_err());
}

#[test]
fn a128kw_header_has_alg_and_enc() {
    let enc_key = jose_aes_kw::a128kw::encryption_key(vec![0x42u8; 16]).unwrap();

    let claims = Claims {
        sub: "hdr".into(),
        admin: false,
    };

    let token = UnsealedToken::<Encrypted<jose_aes_kw::A128Kw, A128Gcm>, Claims>::new(claims);
    let compact = token.encrypt(&enc_key).unwrap();

    let header = compact.header().unwrap();
    assert_eq!(header.alg, "A128KW");
    assert_eq!(header.enc.as_deref(), Some("A128GCM"));
}

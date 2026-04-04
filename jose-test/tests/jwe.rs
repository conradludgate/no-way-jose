use jose_aes_gcm::A256Gcm;
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

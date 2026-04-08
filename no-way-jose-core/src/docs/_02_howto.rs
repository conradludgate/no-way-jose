//! # How-to guides
//!
//! Task-oriented recipes for common JOSE operations.
//!
//! ## Sign and verify a JWS
//!
//! Create a signing key, build a token with claims, sign it, then parse and
//! verify on the receiving side.
//!
//! ```
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::validation::NoValidation;
//! use no_way_jose_core::{CompactJws, UnsignedToken};
//! use no_way_jose_graviola::hmac::Hs256;
//!
//! let secret = b"my-secret-key-at-least-32-bytes!".to_vec();
//! let sk = no_way_jose_graviola::hmac::hs256::symmetric_key(secret.clone()).unwrap();
//! let vk = no_way_jose_graviola::hmac::hs256::verifying_key(secret).unwrap();
//!
//! let token_str = UnsignedToken::<Hs256, RawJson>::new(
//!         RawJson(r#"{"sub":"alice"}"#.into()),
//!     )
//!     .sign(&sk)
//!     .unwrap()
//!     .to_string();
//!
//! let token: CompactJws<Hs256> = token_str.parse().unwrap();
//! let verified = token
//!     .verify(&vk, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(verified.claims.0, r#"{"sub":"alice"}"#);
//! ```
//!
//! ## Encrypt and decrypt a JWE (direct key)
//!
//! With `dir`, a shared symmetric key is used directly as the Content
//! Encryption Key. The key length must match the content encryption
//! algorithm's requirement (e.g. 16 bytes for A128GCM).
//!
//! ```
//! use no_way_jose_core::dir;
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::tokens::{CompactJwe, UnsealedToken};
//! use no_way_jose_core::purpose::Encrypted;
//! use no_way_jose_core::validation::NoValidation;
//! use no_way_jose_graviola::aes_gcm::A128Gcm;
//!
//! let key_bytes = vec![0u8; 16];
//! let enc_key = dir::key(key_bytes.clone());
//! let dec_key = dir::key(key_bytes);
//!
//! let compact = UnsealedToken::<Encrypted<dir::Dir, A128Gcm>, RawJson>::new(
//!         RawJson(r#"{"secret":"data"}"#.into()),
//!     )
//!     .encrypt(&enc_key)
//!     .unwrap();
//!
//! let token_str = compact.to_string();
//!
//! let token: CompactJwe<dir::Dir, A128Gcm> = token_str.parse().unwrap();
//! let unsealed = token
//!     .decrypt(&dec_key, &NoValidation::dangerous_no_validation())
//!     .unwrap();
//! assert_eq!(unsealed.claims.0, r#"{"secret":"data"}"#);
//! ```
//!
//! ## Custom claims with `ToJson` / `FromJson`
//!
//! Implement [`ToJson`] and [`FromJson`] for your own claim type instead
//! of using `RawJson`:
//!
//! ```
//! use no_way_jose_core::json::{ToJson, FromJson, JsonWriter, JsonReader};
//!
//! struct MyClaims {
//!     sub: String,
//!     admin: bool,
//! }
//!
//! impl ToJson for MyClaims {
//!     fn write_json(&self, buf: &mut String) {
//!         let mut w = JsonWriter::new();
//!         w.string("sub", &self.sub);
//!         w.bool("admin", self.admin);
//!         buf.push_str(&w.finish());
//!     }
//! }
//!
//! impl FromJson for MyClaims {
//!     fn from_json_bytes(bytes: &[u8]) -> Result<Self, Box<dyn core::error::Error + Send + Sync>> {
//!         let mut reader = JsonReader::new(bytes)?;
//!         let mut sub = None;
//!         let mut admin = None;
//!         while let Some(key) = reader.next_key()? {
//!             match key {
//!                 "sub" => sub = Some(reader.read_string()?),
//!                 "admin" => admin = Some(reader.read_bool()?),
//!                 _ => reader.skip_value()?,
//!             }
//!         }
//!         Ok(MyClaims {
//!             sub: sub.ok_or("missing sub")?,
//!             admin: admin.ok_or("missing admin")?,
//!         })
//!     }
//! }
//!
//! // Round-trip test
//! let claims = MyClaims { sub: "alice".into(), admin: true };
//! let json = no_way_jose_core::json::ToJson::to_json(&claims);
//! let parsed = MyClaims::from_json_bytes(json.as_bytes()).unwrap();
//! assert_eq!(parsed.sub, "alice");
//! assert!(parsed.admin);
//! ```
//!
//! If you don't need to parse the payload, use [`RawJson`] — it stores
//! the raw bytes without deserialization.
//!
//! [`ToJson`]: crate::json::ToJson
//! [`FromJson`]: crate::json::FromJson
//! [`RawJson`]: crate::json::RawJson
//!
//! ## Build tokens with custom headers
//!
//! Use the builder to set optional header fields like `kid` and `typ`:
//!
//! ```
//! use no_way_jose_core::json::RawJson;
//! use no_way_jose_core::validation::NoValidation;
//! use no_way_jose_core::{CompactJws, UnsignedToken};
//! use no_way_jose_graviola::hmac::Hs256;
//!
//! let sk = no_way_jose_graviola::hmac::hs256::symmetric_key(
//!     b"my-secret-key-at-least-32-bytes!".to_vec(),
//! ).unwrap();
//!
//! let token_str = UnsignedToken::<Hs256, RawJson>::builder(
//!         RawJson(r#"{"sub":"alice"}"#.into()),
//!     )
//!     .kid("my-key-id")
//!     .typ("JWT")
//!     .build()
//!     .sign(&sk)
//!     .unwrap()
//!     .to_string();
//!
//! let token: CompactJws<Hs256> = token_str.parse().unwrap();
//! let header = token.header().unwrap();
//! assert_eq!(header.kid.as_deref(), Some("my-key-id"));
//! assert_eq!(header.typ.as_deref(), Some("JWT"));
//! ```
//!
//! ## JWK import and export
//!
//! Export a key to JWK JSON and import it back:
//!
//! ```
//! use no_way_jose_core::json::ToJson;
//! use no_way_jose_core::jwk::{FromJwk, Jwk, ToJwk};
//! use no_way_jose_graviola::hmac::Hs256;
//!
//! let sk = no_way_jose_graviola::hmac::hs256::symmetric_key(
//!     b"my-secret-key-at-least-32-bytes!".to_vec(),
//! ).unwrap();
//!
//! let jwk: Jwk = sk.to_jwk();
//! let jwk_json = jwk.to_json();
//!
//! let jwk2 = Jwk::from_json(jwk_json.as_bytes()).unwrap();
//! let sk2: no_way_jose_graviola::hmac::hs256::SigningKey = FromJwk::from_jwk(&jwk2).unwrap();
//! # drop(sk2);
//! ```

use alloc::vec::Vec;

use no_way_jose_core::JoseError;
use p256::elliptic_curve::sec1::ToSec1Point;

use crate::epk::EpkFields;

pub(crate) fn p256_ecdh_ephemeral(
    recipient_pub: &p256::PublicKey,
) -> Result<(Vec<u8>, EpkFields), JoseError> {
    use p256::elliptic_curve::Generate;
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let ephemeral_secret = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rng);
    let ephemeral_public = ephemeral_secret.public_key();
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_pub);

    let point = ephemeral_public.to_sec1_point(false);
    let epk = EpkFields {
        kty: "EC",
        crv: "P-256",
        x: point.x().ok_or(JoseError::CryptoError)?.to_vec(),
        y: Some(point.y().ok_or(JoseError::CryptoError)?.to_vec()),
    };

    Ok((shared_secret.raw_secret_bytes().to_vec(), epk))
}

pub(crate) fn p256_ecdh_decrypt(
    secret_key: &p256::SecretKey,
    peer_pub: &p256::PublicKey,
) -> Vec<u8> {
    let shared_secret =
        p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pub.as_affine());
    shared_secret.raw_secret_bytes().to_vec()
}

pub(crate) fn p384_ecdh_ephemeral(
    recipient_pub: &p384::PublicKey,
) -> Result<(Vec<u8>, EpkFields), JoseError> {
    use p256::elliptic_curve::Generate;
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let ephemeral_secret = p384::ecdh::EphemeralSecret::generate_from_rng(&mut rng);
    let ephemeral_public = ephemeral_secret.public_key();
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_pub);

    let point = ephemeral_public.to_sec1_point(false);
    let epk = EpkFields {
        kty: "EC",
        crv: "P-384",
        x: point.x().ok_or(JoseError::CryptoError)?.to_vec(),
        y: Some(point.y().ok_or(JoseError::CryptoError)?.to_vec()),
    };

    Ok((shared_secret.raw_secret_bytes().to_vec(), epk))
}

pub(crate) fn p384_ecdh_decrypt(
    secret_key: &p384::SecretKey,
    peer_pub: &p384::PublicKey,
) -> Vec<u8> {
    let shared_secret =
        p384::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pub.as_affine());
    shared_secret.raw_secret_bytes().to_vec()
}

pub(crate) fn x25519_ecdh_ephemeral(
    recipient_pub: &x25519_dalek::PublicKey,
) -> (Vec<u8>, EpkFields) {
    let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
    let ephemeral_secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_pub);

    let epk = EpkFields {
        kty: "OKP",
        crv: "X25519",
        x: ephemeral_public.as_bytes().to_vec(),
        y: None,
    };

    (shared_secret.as_bytes().to_vec(), epk)
}

pub(crate) fn x25519_ecdh_decrypt(
    secret_key: &x25519_dalek::StaticSecret,
    peer_pub: &x25519_dalek::PublicKey,
) -> Vec<u8> {
    secret_key.diffie_hellman(peer_pub).as_bytes().to_vec()
}

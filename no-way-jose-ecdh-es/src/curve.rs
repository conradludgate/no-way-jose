use alloc::vec::Vec;

use p256::elliptic_curve::sec1::ToSec1Point;

use no_way_jose_core::JoseError;

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
        crv: "P-256",
        x: point.x().ok_or(JoseError::CryptoError)?.to_vec(),
        y: Some(point.y().ok_or(JoseError::CryptoError)?.to_vec()),
    };

    Ok((shared_secret.raw_secret_bytes().to_vec(), epk))
}

pub(crate) fn p256_ecdh_decrypt(
    secret_key: &p256::SecretKey,
    peer_pub: &p256::PublicKey,
) -> Result<Vec<u8>, JoseError> {
    let shared_secret =
        p256::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pub.as_affine());
    Ok(shared_secret.raw_secret_bytes().to_vec())
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
        crv: "P-384",
        x: point.x().ok_or(JoseError::CryptoError)?.to_vec(),
        y: Some(point.y().ok_or(JoseError::CryptoError)?.to_vec()),
    };

    Ok((shared_secret.raw_secret_bytes().to_vec(), epk))
}

pub(crate) fn p384_ecdh_decrypt(
    secret_key: &p384::SecretKey,
    peer_pub: &p384::PublicKey,
) -> Result<Vec<u8>, JoseError> {
    let shared_secret =
        p384::ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), peer_pub.as_affine());
    Ok(shared_secret.raw_secret_bytes().to_vec())
}

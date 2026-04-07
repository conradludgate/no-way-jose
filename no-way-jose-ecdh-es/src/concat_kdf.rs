use alloc::vec::Vec;

use sha2::Digest;

/// Concat KDF (RFC 7518 §4.6.2, NIST SP 800-56A).
///
/// `otherinfo = algId_len(4B) || algId || apu_len(4B) || apu || apv_len(4B) || apv || keydatalen(4B)`
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn concat_kdf(
    shared_secret: &[u8],
    alg: &str,
    key_len: usize,
    apu: &[u8],
    apv: &[u8],
) -> Vec<u8> {
    let keydatalen_bits = (key_len as u32) * 8;

    let mut otherinfo = Vec::new();
    otherinfo.extend_from_slice(&(alg.len() as u32).to_be_bytes());
    otherinfo.extend_from_slice(alg.as_bytes());
    otherinfo.extend_from_slice(&(apu.len() as u32).to_be_bytes());
    otherinfo.extend_from_slice(apu);
    otherinfo.extend_from_slice(&(apv.len() as u32).to_be_bytes());
    otherinfo.extend_from_slice(apv);
    otherinfo.extend_from_slice(&keydatalen_bits.to_be_bytes());

    let hash_len = 32; // SHA-256
    let reps = key_len.div_ceil(hash_len);

    let mut derived = Vec::with_capacity(reps * hash_len);
    for counter in 1..=(reps as u32) {
        let mut hasher = sha2::Sha256::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(shared_secret);
        hasher.update(&otherinfo);
        derived.extend_from_slice(&hasher.finalize());
    }
    derived.truncate(key_len);
    derived
}

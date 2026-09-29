use sha2::{Digest, Sha256};

/// MTProto 2.0 Key Derivation Function (KDF)
/// Evaluates 52-byte stack buffers in a single hardware SHA-256 call.
#[inline(always)]
pub fn kdf_calc(auth_key: &[u8; 256], msg_key: &[u8; 16], is_outgoing: bool) -> ([u8; 32], [u8; 32]) {
    let x: usize = if is_outgoing { 0 } else { 8 };

    // 1. sha256_a = SHA256(msg_key + auth_key[x .. x + 36]) (52 bytes)
    let mut buf_a = [0u8; 52];
    buf_a[0..16].copy_from_slice(msg_key);
    buf_a[16..52].copy_from_slice(&auth_key[x..x + 36]);
    let sha_a = Sha256::digest(buf_a);

    // 2. sha256_b = SHA256(auth_key[40 + x .. 40 + x + 36] + msg_key) (52 bytes)
    let mut buf_b = [0u8; 52];
    buf_b[0..36].copy_from_slice(&auth_key[40 + x..40 + x + 36]);
    buf_b[36..52].copy_from_slice(msg_key);
    let sha_b = Sha256::digest(buf_b);

    let mut aes_key = [0u8; 32];
    let mut aes_iv = [0u8; 32];

    aes_key[0..8].copy_from_slice(&sha_a[0..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_a[24..32]);

    aes_iv[0..8].copy_from_slice(&sha_b[0..8]);
    aes_iv[8..24].copy_from_slice(&sha_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha_b[24..32]);

    (aes_key, aes_iv)
}

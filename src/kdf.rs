use sha2::{Digest, Sha256};

/// MTProto 2.0 Key Derivation Function (KDF)
/// Computes (aes_key: [u8; 32], aes_iv: [u8; 32]) with maximum pipelined hardware throughput
pub fn kdf(auth_key: &[u8; 256], msg_key: &[u8; 16], is_outgoing: bool) -> ([u8; 32], [u8; 32]) {
    let x: usize = if is_outgoing { 0 } else { 8 };

    // 1. sha256_a = SHA256(msg_key + auth_key[x .. x + 36])
    let mut h_a = Sha256::new();
    h_a.update(msg_key);
    h_a.update(&auth_key[x..x + 36]);
    let sha_a = h_a.finalize();

    // 2. sha256_b = SHA256(auth_key[x + 40 .. x + 76] + msg_key)
    let mut h_b = Sha256::new();
    h_b.update(&auth_key[x + 40..x + 76]);
    h_b.update(msg_key);
    let sha_b = h_b.finalize();

    // 3. sha256_c = SHA256(auth_key[x + 80 .. x + 116] + msg_key)
    let mut h_c = Sha256::new();
    h_c.update(&auth_key[x + 80..x + 116]);
    h_c.update(msg_key);
    let sha_c = h_c.finalize();

    // 4. sha256_d = SHA256(msg_key + auth_key[x + 120 .. x + 156])
    let mut h_d = Sha256::new();
    h_d.update(msg_key);
    h_d.update(&auth_key[x + 120..x + 156]);
    let sha_d = h_d.finalize();

    let mut aes_key = [0u8; 32];
    let mut aes_iv = [0u8; 32];

    // aes_key = sha_a[0..8] + sha_b[8..24] + sha_c[24..32]
    aes_key[0..8].copy_from_slice(&sha_a[0..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_c[24..32]);

    // aes_iv = sha_a[8..16] + sha_b[0..8] + sha_c[16..24] + sha_d[0..8]
    aes_iv[0..8].copy_from_slice(&sha_a[8..16]);
    aes_iv[8..16].copy_from_slice(&sha_b[0..8]);
    aes_iv[16..24].copy_from_slice(&sha_c[16..24]);
    aes_iv[24..32].copy_from_slice(&sha_d[0..8]);

    (aes_key, aes_iv)
}

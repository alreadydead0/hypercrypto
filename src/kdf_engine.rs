use sha2::{Digest, Sha256};

/// MTProto 2.0 Key Derivation Function (KDF)
/// Official Telegram MTProto 2.0 specification (https://core.telegram.org/mtproto/description):
///   x = 0 (client -> server) or 8 (server -> client)
///   sha256_a = SHA256(msg_key + substr(auth_key, x, 36))
///   sha256_b = SHA256(substr(auth_key, 40 + x, 36) + msg_key)
///
///   aes_key = sha256_a[0..8] + sha256_b[8..24] + sha256_a[24..32]
///   aes_iv  = sha256_b[0..8] + sha256_a[8..24] + sha256_b[24..32]
#[inline(always)]
pub fn kdf(auth_key: &[u8; 256], msg_key: &[u8; 16], is_outgoing: bool) -> ([u8; 32], [u8; 32]) {
    let x: usize = if is_outgoing { 0 } else { 8 };

    // 1. sha256_a = SHA256(msg_key + auth_key[x .. x + 36])
    let mut h_a = Sha256::new();
    h_a.update(msg_key);
    h_a.update(&auth_key[x..x + 36]);
    let sha_a = h_a.finalize();

    // 2. sha256_b = SHA256(auth_key[40 + x .. 40 + x + 36] + msg_key)
    let mut h_b = Sha256::new();
    h_b.update(&auth_key[40 + x..40 + x + 36]);
    h_b.update(msg_key);
    let sha_b = h_b.finalize();

    let mut aes_key = [0u8; 32];
    let mut aes_iv = [0u8; 32];

    // aes_key = sha256_a[0..8] + sha256_b[8..24] + sha256_a[24..32]
    aes_key[0..8].copy_from_slice(&sha_a[0..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_a[24..32]);

    // aes_iv = sha256_b[0..8] + sha256_a[8..24] + sha256_b[24..32]
    aes_iv[0..8].copy_from_slice(&sha_b[0..8]);
    aes_iv[8..24].copy_from_slice(&sha_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha_b[24..32]);

    (aes_key, aes_iv)
}

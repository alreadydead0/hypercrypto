use sha2::{Digest, Sha256};
use crate::aes_ige::{ige256_decrypt_inplace, ige256_encrypt_inplace};
use crate::kdf::kdf;

/// High-speed MTProto 2.0 message packing (Padding -> MsgKey -> KDF -> AES-IGE)
pub fn pack_message(auth_key: &[u8; 256], message: &[u8], is_outgoing: bool) -> Vec<u8> {
    let auth_key_id = &auth_key[auth_key.len() - 8..]; // Last 8 bytes
    let msg_len = message.len();

    // 1. Calculate padding (between 12 and 1024 bytes such that total data is multiple of 16)
    let padding_len = 16 - (msg_len % 16);
    let total_padding = if padding_len < 12 { padding_len + 16 } else { padding_len };
    let total_len = msg_len + total_padding;

    // 2. Prepare unencrypted buffer [message + padding]
    let mut data = Vec::with_capacity(total_len);
    data.extend_from_slice(message);
    // Fill padding with deterministic or random bytes
    for i in 0..total_padding {
        data.push((i as u8).wrapping_add(0x42));
    }

    // 3. msg_key = SHA256(auth_key[88..120] + data)[0..16] (for client outgoing)
    let x = if is_outgoing { 88 } else { 96 };
    let mut hasher = Sha256::new();
    hasher.update(&auth_key[x..x + 32]);
    hasher.update(&data);
    let full_sha = hasher.finalize();
    let msg_key: [u8; 16] = full_sha[..16].try_into().unwrap();

    // 4. Derive keys using KDF
    let (aes_key, aes_iv) = kdf(auth_key, &msg_key, is_outgoing);

    // 5. In-place AES-256-IGE encrypt
    ige256_encrypt_inplace(&mut data, &aes_key, &aes_iv);

    // 6. Assemble final packet: [auth_key_id (8B) + msg_key (16B) + encrypted_data]
    let mut result = Vec::with_capacity(8 + 16 + data.len());
    result.extend_from_slice(auth_key_id);
    result.extend_from_slice(&msg_key);
    result.extend_from_slice(&data);

    result
}

/// High-speed MTProto 2.0 message unpacking (AES-IGE Decrypt -> MsgKey Validation)
pub fn unpack_message(auth_key: &[u8; 256], encrypted_packet: &[u8], is_outgoing: bool) -> Result<Vec<u8>, &'static str> {
    if encrypted_packet.len() < 24 + 16 {
        return Err("Encrypted packet too short");
    }

    let _auth_key_id = &encrypted_packet[0..8];
    let msg_key: [u8; 16] = encrypted_packet[8..24].try_into().unwrap();
    let mut encrypted_data = encrypted_packet[24..].to_vec();

    if encrypted_data.len() % 16 != 0 {
        return Err("Payload length is not a multiple of 16");
    }

    // 1. Derive keys using KDF
    let (aes_key, aes_iv) = kdf(auth_key, &msg_key, is_outgoing);

    // 2. In-place AES-256-IGE decrypt
    ige256_decrypt_inplace(&mut encrypted_data, &aes_key, &aes_iv);

    // 3. Verify msg_key: SHA256(auth_key[x..x+32] + decrypted_data)[0..16] == msg_key
    let x = if is_outgoing { 88 } else { 96 };
    let mut hasher = Sha256::new();
    hasher.update(&auth_key[x..x + 32]);
    hasher.update(&encrypted_data);
    let full_sha = hasher.finalize();

    if &full_sha[0..16] != &msg_key[..] {
        return Err("Invalid msg_key: checksum verification failed");
    }

    Ok(encrypted_data)
}

use sha2::{Digest, Sha256};
use crate::aes_ige::{ige256_decrypt_inplace, ige256_encrypt_inplace};
use crate::kdf_core::kdf_calc;

#[inline(always)]
pub fn pack_message_into(auth_key: &[u8; 256], message: &[u8], is_outgoing: bool, out: &mut [u8]) {
    let msg_len = message.len();
    let padding_len = 16 - (msg_len % 16);
    let total_padding = if padding_len < 12 { padding_len + 16 } else { padding_len };

    let payload = &mut out[16..16 + msg_len + total_padding];
    payload[..msg_len].copy_from_slice(message);
    for i in 0..total_padding {
        payload[msg_len + i] = (i as u8).wrapping_add(0x42);
    }

    let x = if is_outgoing { 88 } else { 96 };
    let mut hasher = Sha256::new();
    hasher.update(&auth_key[x..x + 32]);
    hasher.update(&*payload);
    let full_sha = hasher.finalize();
    let msg_key: [u8; 16] = full_sha[8..24].try_into().unwrap();

    let (aes_key, aes_iv) = kdf_calc(auth_key, &msg_key, is_outgoing);
    ige256_encrypt_inplace(payload, &aes_key, &aes_iv);

    out[..16].copy_from_slice(&msg_key);
}

#[inline(always)]
pub fn unpack_message_into(auth_key: &[u8; 256], encrypted_packet: &[u8], is_outgoing: bool, out: &mut [u8]) -> Result<usize, &'static str> {
    if encrypted_packet.len() < 32 {
        return Err("Encrypted packet too short");
    }

    let msg_key: [u8; 16] = encrypted_packet[0..16].try_into().unwrap();
    let payload = &encrypted_packet[16..];

    if payload.len() % 16 != 0 {
        return Err("Payload length is not a multiple of 16");
    }

    out[..payload.len()].copy_from_slice(payload);
    let decrypted = &mut out[..payload.len()];

    let (aes_key, aes_iv) = kdf_calc(auth_key, &msg_key, is_outgoing);
    ige256_decrypt_inplace(decrypted, &aes_key, &aes_iv);

    let x = if is_outgoing { 88 } else { 96 };
    let mut hasher = Sha256::new();
    hasher.update(&auth_key[x..x + 32]);
    hasher.update(&*decrypted);
    let full_sha = hasher.finalize();

    if &full_sha[8..24] != &msg_key[..] {
        return Err("Invalid msg_key: checksum verification failed");
    }

    Ok(payload.len())
}

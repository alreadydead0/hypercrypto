use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

/// In-place AES-256-IGE Encryption
/// Optimized for zero intermediate buffer allocations and maximum CPU cache locality.
#[inline(always)]
pub fn ige256_encrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let chunks = data.chunks_exact_mut(16);
    for chunk in chunks {
        let p_chunk: &mut [u8; 16] = chunk.try_into().unwrap();
        let p_orig = *p_chunk;

        // 1. p_chunk = p_i ^ iv1
        for i in 0..16 {
            p_chunk[i] ^= iv1[i];
        }

        // 2. p_chunk = E(p_i ^ iv1) in-place
        cipher.encrypt_block(GenericArray::from_mut_slice(p_chunk));

        // 3. c_i = E(p_i ^ iv1) ^ iv2 in-place
        for i in 0..16 {
            p_chunk[i] ^= iv2[i];
        }

        // 4. Update IVs
        iv1 = *p_chunk;
        iv2 = p_orig;
    }
}

/// In-place AES-256-IGE Decryption
/// Optimized for zero intermediate buffer allocations and maximum CPU cache locality.
#[inline(always)]
pub fn ige256_decrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let chunks = data.chunks_exact_mut(16);
    for chunk in chunks {
        let c_chunk: &mut [u8; 16] = chunk.try_into().unwrap();
        let c_orig = *c_chunk;

        // 1. c_chunk = c_i ^ iv2
        for i in 0..16 {
            c_chunk[i] ^= iv2[i];
        }

        // 2. c_chunk = D(c_i ^ iv2) in-place
        cipher.decrypt_block(GenericArray::from_mut_slice(c_chunk));

        // 3. p_i = D(c_i ^ iv2) ^ iv1 in-place
        for i in 0..16 {
            c_chunk[i] ^= iv1[i];
        }

        // 4. Update IVs
        iv1 = c_orig;
        iv2 = *c_chunk;
    }
}

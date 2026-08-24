use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

/// Ultra-low latency In-place AES-256-IGE Encryption
/// Zero branch overhead and zero intermediate buffers.
#[inline(always)]
pub fn ige256_encrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let num_blocks = data.len() / 16;
    let ptr = data.as_mut_ptr() as *mut [u8; 16];

    for i in 0..num_blocks {
        let p_chunk = unsafe { &mut *ptr.add(i) };
        let p_orig = *p_chunk;

        for j in 0..16 {
            p_chunk[j] ^= iv1[j];
        }

        cipher.encrypt_block(GenericArray::from_mut_slice(p_chunk));

        for j in 0..16 {
            p_chunk[j] ^= iv2[j];
        }

        iv1 = *p_chunk;
        iv2 = p_orig;
    }
}

/// Ultra-low latency In-place AES-256-IGE Decryption
/// Zero branch overhead and zero intermediate buffers.
#[inline(always)]
pub fn ige256_decrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let num_blocks = data.len() / 16;
    let ptr = data.as_mut_ptr() as *mut [u8; 16];

    for i in 0..num_blocks {
        let c_chunk = unsafe { &mut *ptr.add(i) };
        let c_orig = *c_chunk;

        for j in 0..16 {
            c_chunk[j] ^= iv2[j];
        }

        cipher.decrypt_block(GenericArray::from_mut_slice(c_chunk));

        for j in 0..16 {
            c_chunk[j] ^= iv1[j];
        }

        iv1 = c_orig;
        iv2 = *c_chunk;
    }
}

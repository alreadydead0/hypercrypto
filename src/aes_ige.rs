use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

/// In-place AES-256-IGE Encryption
/// 
/// # Safety & Invariants:
/// - `data` length must be a multiple of 16 bytes.
/// - Pointer arithmetic `ptr.add(i)` strictly accesses `[0 .. num_blocks * 16]`, perfectly bounded within `data`.
/// - Automatic runtime hardware acceleration (AES-NI / ARMv8 Crypto) via `aes` crate with safe portable fallback.
#[inline(always)]
pub fn ige256_encrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0, "IGE data length must be a multiple of 16");
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let num_blocks = data.len() / 16;
    let ptr = data.as_mut_ptr() as *mut [u8; 16];

    for i in 0..num_blocks {
        // SAFETY: `i < num_blocks` ensures `ptr.add(i)` is within `data` bounds.
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

/// In-place AES-256-IGE Decryption
/// 
/// # Safety & Invariants:
/// - `data` length must be a multiple of 16 bytes.
/// - Pointer arithmetic `ptr.add(i)` strictly accesses `[0 .. num_blocks * 16]`, perfectly bounded within `data`.
/// - Automatic runtime hardware acceleration (AES-NI / ARMv8 Crypto) via `aes` crate with safe portable fallback.
#[inline(always)]
pub fn ige256_decrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0, "IGE data length must be a multiple of 16");
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let num_blocks = data.len() / 16;
    let ptr = data.as_mut_ptr() as *mut [u8; 16];

    for i in 0..num_blocks {
        // SAFETY: `i < num_blocks` ensures `ptr.add(i)` is within `data` bounds.
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

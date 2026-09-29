use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes256Dec, Aes256Enc};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "x86_64")]
mod ni {
    use super::*;

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn expand_key_256(key: &[u8; 32]) -> ([__m128i; 15], [__m128i; 15]) {
        let mut enc = [_mm_setzero_si128(); 15];
        let mut dec = [_mm_setzero_si128(); 15];

        let mut t1 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let mut t3 = _mm_loadu_si128(key.as_ptr().add(16) as *const __m128i);

        enc[0] = t1;
        enc[1] = t3;

        macro_rules! round1 {
            ($rcon:expr, $idx:expr) => {
                let t2 = _mm_aeskeygenassist_si128(t3, $rcon);
                let t2 = _mm_shuffle_epi32(t2, 0xff);
                t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
                t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
                t1 = _mm_xor_si128(t1, _mm_slli_si128(t1, 4));
                t1 = _mm_xor_si128(t1, t2);
                enc[$idx] = t1;
            };
        }

        macro_rules! round2 {
            ($idx:expr) => {
                let t2 = _mm_aeskeygenassist_si128(t1, 0x00);
                let t2 = _mm_shuffle_epi32(t2, 0xaa);
                t3 = _mm_xor_si128(t3, _mm_slli_si128(t3, 4));
                t3 = _mm_xor_si128(t3, _mm_slli_si128(t3, 4));
                t3 = _mm_xor_si128(t3, _mm_slli_si128(t3, 4));
                t3 = _mm_xor_si128(t3, t2);
                enc[$idx] = t3;
            };
        }

        round1!(0x01, 2); round2!(3);
        round1!(0x02, 4); round2!(5);
        round1!(0x04, 6); round2!(7);
        round1!(0x08, 8); round2!(9);
        round1!(0x10, 10); round2!(11);
        round1!(0x20, 12); round2!(13);
        round1!(0x40, 14);

        dec[0] = enc[14];
        for i in 1..14 {
            dec[i] = _mm_aesimc_si128(enc[14 - i]);
        }
        dec[14] = enc[0];

        (enc, dec)
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn encrypt_block(mut b: __m128i, k: &[__m128i; 15]) -> __m128i {
        b = _mm_xor_si128(b, k[0]);
        b = _mm_aesenc_si128(b, k[1]);
        b = _mm_aesenc_si128(b, k[2]);
        b = _mm_aesenc_si128(b, k[3]);
        b = _mm_aesenc_si128(b, k[4]);
        b = _mm_aesenc_si128(b, k[5]);
        b = _mm_aesenc_si128(b, k[6]);
        b = _mm_aesenc_si128(b, k[7]);
        b = _mm_aesenc_si128(b, k[8]);
        b = _mm_aesenc_si128(b, k[9]);
        b = _mm_aesenc_si128(b, k[10]);
        b = _mm_aesenc_si128(b, k[11]);
        b = _mm_aesenc_si128(b, k[12]);
        b = _mm_aesenc_si128(b, k[13]);
        _mm_aesenclast_si128(b, k[14])
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn decrypt_block(mut b: __m128i, k: &[__m128i; 15]) -> __m128i {
        b = _mm_xor_si128(b, k[0]);
        b = _mm_aesdec_si128(b, k[1]);
        b = _mm_aesdec_si128(b, k[2]);
        b = _mm_aesdec_si128(b, k[3]);
        b = _mm_aesdec_si128(b, k[4]);
        b = _mm_aesdec_si128(b, k[5]);
        b = _mm_aesdec_si128(b, k[6]);
        b = _mm_aesdec_si128(b, k[7]);
        b = _mm_aesdec_si128(b, k[8]);
        b = _mm_aesdec_si128(b, k[9]);
        b = _mm_aesdec_si128(b, k[10]);
        b = _mm_aesdec_si128(b, k[11]);
        b = _mm_aesdec_si128(b, k[12]);
        b = _mm_aesdec_si128(b, k[13]);
        _mm_aesdeclast_si128(b, k[14])
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn ige256_encrypt_inplace(data: &mut [u8], enc_keys: &[__m128i; 15], iv: &[u8; 32]) {
        let mut iv1 = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
        let mut iv2 = _mm_loadu_si128(iv.as_ptr().add(16) as *const __m128i);

        let num_blocks = data.len() / 16;
        let ptr = data.as_mut_ptr() as *mut __m128i;

        for i in 0..num_blocks {
            let p_orig = _mm_loadu_si128(ptr.add(i));
            let x = _mm_xor_si128(p_orig, iv1);
            let c = encrypt_block(x, enc_keys);
            let res = _mm_xor_si128(c, iv2);
            _mm_storeu_si128(ptr.add(i), res);
            iv1 = res;
            iv2 = p_orig;
        }
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn ige256_decrypt_inplace(data: &mut [u8], dec_keys: &[__m128i; 15], iv: &[u8; 32]) {
        let mut iv1 = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
        let mut iv2 = _mm_loadu_si128(iv.as_ptr().add(16) as *const __m128i);

        let num_blocks = data.len() / 16;
        let ptr = data.as_mut_ptr() as *mut __m128i;

        for i in 0..num_blocks {
            let c_orig = _mm_loadu_si128(ptr.add(i));
            let x = _mm_xor_si128(c_orig, iv2);
            let m = decrypt_block(x, dec_keys);
            let res = _mm_xor_si128(m, iv1);
            _mm_storeu_si128(ptr.add(i), res);
            iv1 = c_orig;
            iv2 = res;
        }
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn ige256_encrypt_slice(src: &[u8], dst: &mut [u8], enc_keys: &[__m128i; 15], iv: &[u8; 32]) {
        let mut iv1 = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
        let mut iv2 = _mm_loadu_si128(iv.as_ptr().add(16) as *const __m128i);

        let num_blocks = src.len() / 16;
        let src_ptr = src.as_ptr() as *const __m128i;
        let dst_ptr = dst.as_mut_ptr() as *mut __m128i;

        for i in 0..num_blocks {
            let p_orig = _mm_loadu_si128(src_ptr.add(i));
            let x = _mm_xor_si128(p_orig, iv1);
            let c = encrypt_block(x, enc_keys);
            let res = _mm_xor_si128(c, iv2);
            _mm_storeu_si128(dst_ptr.add(i), res);
            iv1 = res;
            iv2 = p_orig;
        }
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn ige256_decrypt_slice(src: &[u8], dst: &mut [u8], dec_keys: &[__m128i; 15], iv: &[u8; 32]) {
        let mut iv1 = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
        let mut iv2 = _mm_loadu_si128(iv.as_ptr().add(16) as *const __m128i);

        let num_blocks = src.len() / 16;
        let src_ptr = src.as_ptr() as *const __m128i;
        let dst_ptr = dst.as_mut_ptr() as *mut __m128i;

        for i in 0..num_blocks {
            let c_orig = _mm_loadu_si128(src_ptr.add(i));
            let x = _mm_xor_si128(c_orig, iv2);
            let m = decrypt_block(x, dec_keys);
            let res = _mm_xor_si128(m, iv1);
            _mm_storeu_si128(dst_ptr.add(i), res);
            iv1 = c_orig;
            iv2 = res;
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Safe Portable Fallback (Zero bounds checks, u128 vectorized XORs)
// -------------------------------------------------------------------------------------------------

#[inline(always)]
fn ige256_encrypt_fallback(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    let cipher = Aes256Enc::new(GenericArray::from_slice(key));
    let mut iv1 = u128::from_ne_bytes(iv[0..16].try_into().unwrap());
    let mut iv2 = u128::from_ne_bytes(iv[16..32].try_into().unwrap());

    let num_blocks = data.len() / 16;
    let ptr = data.as_mut_ptr() as *mut u128;

    for i in 0..num_blocks {
        let p_orig = unsafe { ptr.add(i).read_unaligned() };
        let x = p_orig ^ iv1;
        unsafe { ptr.add(i).write_unaligned(x) };

        cipher.encrypt_block(unsafe { &mut *(ptr.add(i) as *mut GenericArray<u8, aes::cipher::typenum::U16>) });

        let c = unsafe { ptr.add(i).read_unaligned() };
        let res = c ^ iv2;
        unsafe { ptr.add(i).write_unaligned(res) };

        iv1 = res;
        iv2 = p_orig;
    }
}

#[inline(always)]
fn ige256_decrypt_fallback(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    let cipher = Aes256Dec::new(GenericArray::from_slice(key));
    let mut iv1 = u128::from_ne_bytes(iv[0..16].try_into().unwrap());
    let mut iv2 = u128::from_ne_bytes(iv[16..32].try_into().unwrap());

    let num_blocks = data.len() / 16;
    let ptr = data.as_mut_ptr() as *mut u128;

    for i in 0..num_blocks {
        let c_orig = unsafe { ptr.add(i).read_unaligned() };
        let x = c_orig ^ iv2;
        unsafe { ptr.add(i).write_unaligned(x) };

        cipher.decrypt_block(unsafe { &mut *(ptr.add(i) as *mut GenericArray<u8, aes::cipher::typenum::U16>) });

        let m = unsafe { ptr.add(i).read_unaligned() };
        let res = m ^ iv1;
        unsafe { ptr.add(i).write_unaligned(res) };

        iv1 = c_orig;
        iv2 = res;
    }
}

#[inline(always)]
fn ige256_encrypt_slice_fallback(src: &[u8], dst: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    dst.copy_from_slice(src);
    ige256_encrypt_fallback(dst, key, iv);
}

#[inline(always)]
fn ige256_decrypt_slice_fallback(src: &[u8], dst: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    dst.copy_from_slice(src);
    ige256_decrypt_fallback(dst, key, iv);
}

// -------------------------------------------------------------------------------------------------
// Public Dispatch APIs
// -------------------------------------------------------------------------------------------------

/// In-place AES-256-IGE Encryption with automatic hardware acceleration
#[inline(always)]
pub fn ige256_encrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0, "IGE data length must be a multiple of 16");

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            unsafe {
                let (enc_keys, _) = ni::expand_key_256(key);
                ni::ige256_encrypt_inplace(data, &enc_keys, iv);
            }
            return;
        }
    }

    ige256_encrypt_fallback(data, key, iv);
}

/// In-place AES-256-IGE Decryption with automatic hardware acceleration
#[inline(always)]
pub fn ige256_decrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0, "IGE data length must be a multiple of 16");

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            unsafe {
                let (_, dec_keys) = ni::expand_key_256(key);
                ni::ige256_decrypt_inplace(data, &dec_keys, iv);
            }
            return;
        }
    }

    ige256_decrypt_fallback(data, key, iv);
}

/// Single-Pass Out-of-Place AES-256-IGE Encryption (Zero intermediate buffer copy)
#[inline(always)]
pub fn ige256_encrypt_slice(src: &[u8], dst: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(src.len() % 16 == 0 && dst.len() >= src.len());

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            unsafe {
                let (enc_keys, _) = ni::expand_key_256(key);
                ni::ige256_encrypt_slice(src, dst, &enc_keys, iv);
            }
            return;
        }
    }

    ige256_encrypt_slice_fallback(src, dst, key, iv);
}

/// Single-Pass Out-of-Place AES-256-IGE Decryption (Zero intermediate buffer copy)
#[inline(always)]
pub fn ige256_decrypt_slice(src: &[u8], dst: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(src.len() % 16 == 0 && dst.len() >= src.len());

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            unsafe {
                let (_, dec_keys) = ni::expand_key_256(key);
                ni::ige256_decrypt_slice(src, dst, &dec_keys, iv);
            }
            return;
        }
    }

    ige256_decrypt_slice_fallback(src, dst, key, iv);
}

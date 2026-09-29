use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256Enc;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[inline(always)]
pub fn increment_counter(iv: &mut [u8; 16]) {
    let val = u128::from_be_bytes(*iv).wrapping_add(1);
    *iv = val.to_be_bytes();
}

#[cfg(target_arch = "x86_64")]
mod ni {
    use super::*;

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn expand_enc_key_256(key: &[u8; 32]) -> [__m128i; 15] {
        let mut enc = [_mm_setzero_si128(); 15];
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
        enc
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn encrypt_8_blocks(b: &mut [__m128i; 8], keys: &[__m128i; 15]) {
        let k0 = keys[0];
        for i in 0..8 { b[i] = _mm_xor_si128(b[i], k0); }

        for r in 1..14 {
            let kr = keys[r];
            for i in 0..8 { b[i] = _mm_aesenc_si128(b[i], kr); }
        }

        let k14 = keys[14];
        for i in 0..8 { b[i] = _mm_aesenclast_si128(b[i], k14); }
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn encrypt_4_blocks(b: &mut [__m128i; 4], keys: &[__m128i; 15]) {
        let k0 = keys[0];
        for i in 0..4 { b[i] = _mm_xor_si128(b[i], k0); }

        for r in 1..14 {
            let kr = keys[r];
            for i in 0..4 { b[i] = _mm_aesenc_si128(b[i], kr); }
        }

        let k14 = keys[14];
        for i in 0..4 { b[i] = _mm_aesenclast_si128(b[i], k14); }
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn encrypt_1_block(mut b: __m128i, keys: &[__m128i; 15]) -> __m128i {
        b = _mm_xor_si128(b, keys[0]);
        for r in 1..14 {
            b = _mm_aesenc_si128(b, keys[r]);
        }
        _mm_aesenclast_si128(b, keys[14])
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn ctr256_process(
        data: &[u8],
        keys: &[__m128i; 15],
        iv: &mut [u8; 16],
        state: &mut [u8],
        out: &mut [u8],
    ) {
        let data_len = data.len();
        if data_len == 0 {
            return;
        }

        let mut offset = (state[0] & 0x0F) as usize;
        let mut data_idx = 0;

        // Drain active partial block if offset != 0
        if offset > 0 {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            let ks = encrypt_1_block(iv_b, keys);
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);

            let take = std::cmp::min(data_len, 16 - offset);
            for i in 0..take {
                out[data_idx + i] = data[data_idx + i] ^ ks_bytes[offset + i];
            }
            data_idx += take;
            offset = (offset + take) % 16;
            if offset == 0 {
                increment_counter(iv);
            }
        }

        // 8-Way Unrolled Parallel Processing (128 bytes at once)
        while data_idx + 128 <= data_len {
            let mut blocks = [_mm_setzero_si128(); 8];
            for i in 0..8 {
                blocks[i] = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
                increment_counter(iv);
            }

            encrypt_8_blocks(&mut blocks, keys);

            for i in 0..8 {
                let d = _mm_loadu_si128(data.as_ptr().add(data_idx + i * 16) as *const __m128i);
                let x = _mm_xor_si128(d, blocks[i]);
                _mm_storeu_si128(out.as_mut_ptr().add(data_idx + i * 16) as *mut __m128i, x);
            }
            data_idx += 128;
        }

        // 4-Way Unrolled Processing (64 bytes at once)
        while data_idx + 64 <= data_len {
            let mut blocks = [_mm_setzero_si128(); 4];
            for i in 0..4 {
                blocks[i] = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
                increment_counter(iv);
            }

            encrypt_4_blocks(&mut blocks, keys);

            for i in 0..4 {
                let d = _mm_loadu_si128(data.as_ptr().add(data_idx + i * 16) as *const __m128i);
                let x = _mm_xor_si128(d, blocks[i]);
                _mm_storeu_si128(out.as_mut_ptr().add(data_idx + i * 16) as *mut __m128i, x);
            }
            data_idx += 64;
        }

        // Single Block Processing (16 bytes)
        while data_idx + 16 <= data_len {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            increment_counter(iv);
            let ks = encrypt_1_block(iv_b, keys);

            let d = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            let x = _mm_xor_si128(d, ks);
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx) as *mut __m128i, x);
            data_idx += 16;
        }

        // Trailing bytes (< 16 bytes)
        if data_idx < data_len {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            let ks = encrypt_1_block(iv_b, keys);
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);

            let rem = data_len - data_idx;
            for j in 0..rem {
                out[data_idx + j] = data[data_idx + j] ^ ks_bytes[j];
            }
            offset = rem;
        }

        state[0] = offset as u8;
    }

    #[target_feature(enable = "aes", enable = "sse2")]
    pub unsafe fn ctr256_process_inplace(
        data: &mut [u8],
        keys: &[__m128i; 15],
        iv: &mut [u8; 16],
        state: &mut [u8],
    ) {
        let data_len = data.len();
        if data_len == 0 {
            return;
        }

        let mut offset = (state[0] & 0x0F) as usize;
        let mut data_idx = 0;

        if offset > 0 {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            let ks = encrypt_1_block(iv_b, keys);
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);

            let take = std::cmp::min(data_len, 16 - offset);
            for i in 0..take {
                data[data_idx + i] ^= ks_bytes[offset + i];
            }
            data_idx += take;
            offset = (offset + take) % 16;
            if offset == 0 {
                increment_counter(iv);
            }
        }

        while data_idx + 128 <= data_len {
            let mut blocks = [_mm_setzero_si128(); 8];
            for i in 0..8 {
                blocks[i] = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
                increment_counter(iv);
            }

            encrypt_8_blocks(&mut blocks, keys);

            for i in 0..8 {
                let d = _mm_loadu_si128(data.as_ptr().add(data_idx + i * 16) as *const __m128i);
                let x = _mm_xor_si128(d, blocks[i]);
                _mm_storeu_si128(data.as_mut_ptr().add(data_idx + i * 16) as *mut __m128i, x);
            }
            data_idx += 128;
        }

        while data_idx + 64 <= data_len {
            let mut blocks = [_mm_setzero_si128(); 4];
            for i in 0..4 {
                blocks[i] = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
                increment_counter(iv);
            }

            encrypt_4_blocks(&mut blocks, keys);

            for i in 0..4 {
                let d = _mm_loadu_si128(data.as_ptr().add(data_idx + i * 16) as *const __m128i);
                let x = _mm_xor_si128(d, blocks[i]);
                _mm_storeu_si128(data.as_mut_ptr().add(data_idx + i * 16) as *mut __m128i, x);
            }
            data_idx += 64;
        }

        while data_idx + 16 <= data_len {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            increment_counter(iv);
            let ks = encrypt_1_block(iv_b, keys);

            let d = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            let x = _mm_xor_si128(d, ks);
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx) as *mut __m128i, x);
            data_idx += 16;
        }

        if data_idx < data_len {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            let ks = encrypt_1_block(iv_b, keys);
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);

            let rem = data_len - data_idx;
            for j in 0..rem {
                data[data_idx + j] ^= ks_bytes[j];
            }
            offset = rem;
        }

        state[0] = offset as u8;
    }
}

// -------------------------------------------------------------------------------------------------
// Safe Portable Fallback (aes crate)
// -------------------------------------------------------------------------------------------------

fn ctr256_process_fallback(
    data: &[u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut [u8],
    out: &mut [u8],
) {
    let data_len = data.len();
    if data_len == 0 {
        return;
    }

    let cipher = Aes256Enc::new(GenericArray::from_slice(key));
    let mut offset = (state[0] & 0x0F) as usize;
    let mut data_idx = 0;

    if offset > 0 {
        let mut block = *GenericArray::from_slice(iv);
        cipher.encrypt_block(&mut block);
        let take = std::cmp::min(data_len, 16 - offset);
        for i in 0..take {
            out[data_idx + i] = data[data_idx + i] ^ block[offset + i];
        }
        data_idx += take;
        offset = (offset + take) % 16;
        if offset == 0 {
            increment_counter(iv);
        }
    }

    while data_idx + 128 <= data_len {
        let mut blocks = [GenericArray::<u8, aes::cipher::typenum::U16>::default(); 8];
        for i in 0..8 {
            blocks[i] = *GenericArray::from_slice(iv);
            increment_counter(iv);
        }
        cipher.encrypt_blocks(&mut blocks);
        for i in 0..8 {
            let chunk_in = &data[data_idx + i * 16..data_idx + (i + 1) * 16];
            let chunk_out = &mut out[data_idx + i * 16..data_idx + (i + 1) * 16];
            let ks = &blocks[i];
            for j in 0..16 {
                chunk_out[j] = chunk_in[j] ^ ks[j];
            }
        }
        data_idx += 128;
    }

    while data_idx + 16 <= data_len {
        let mut block = *GenericArray::from_slice(iv);
        increment_counter(iv);
        cipher.encrypt_block(&mut block);
        for j in 0..16 {
            out[data_idx + j] = data[data_idx + j] ^ block[j];
        }
        data_idx += 16;
    }

    if data_idx < data_len {
        let mut block = *GenericArray::from_slice(iv);
        cipher.encrypt_block(&mut block);
        let rem = data_len - data_idx;
        for j in 0..rem {
            out[data_idx + j] = data[data_idx + j] ^ block[j];
        }
        offset = rem;
    }

    state[0] = offset as u8;
}

fn ctr256_process_inplace_fallback(
    data: &mut [u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut [u8],
) {
    let data_len = data.len();
    if data_len == 0 {
        return;
    }

    let cipher = Aes256Enc::new(GenericArray::from_slice(key));
    let mut offset = (state[0] & 0x0F) as usize;
    let mut data_idx = 0;

    if offset > 0 {
        let mut block = *GenericArray::from_slice(iv);
        cipher.encrypt_block(&mut block);
        let take = std::cmp::min(data_len, 16 - offset);
        for i in 0..take {
            data[data_idx + i] ^= block[offset + i];
        }
        data_idx += take;
        offset = (offset + take) % 16;
        if offset == 0 {
            increment_counter(iv);
        }
    }

    while data_idx + 128 <= data_len {
        let mut blocks = [GenericArray::<u8, aes::cipher::typenum::U16>::default(); 8];
        for i in 0..8 {
            blocks[i] = *GenericArray::from_slice(iv);
            increment_counter(iv);
        }
        cipher.encrypt_blocks(&mut blocks);
        for i in 0..8 {
            let chunk = &mut data[data_idx + i * 16..data_idx + (i + 1) * 16];
            let ks = &blocks[i];
            for j in 0..16 {
                chunk[j] ^= ks[j];
            }
        }
        data_idx += 128;
    }

    while data_idx + 16 <= data_len {
        let mut block = *GenericArray::from_slice(iv);
        increment_counter(iv);
        cipher.encrypt_block(&mut block);
        for j in 0..16 {
            data[data_idx + j] ^= block[j];
        }
        data_idx += 16;
    }

    if data_idx < data_len {
        let mut block = *GenericArray::from_slice(iv);
        cipher.encrypt_block(&mut block);
        let rem = data_len - data_idx;
        for j in 0..rem {
            data[data_idx + j] ^= block[j];
        }
        offset = rem;
    }

    state[0] = offset as u8;
}

// -------------------------------------------------------------------------------------------------
// Public APIs
// -------------------------------------------------------------------------------------------------

/// High-throughput AES-256-CTR processor with automatic hardware acceleration
#[inline(always)]
pub fn ctr256_process(
    data: &[u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut [u8],
    out: &mut [u8],
) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            unsafe {
                let keys = ni::expand_enc_key_256(key);
                ni::ctr256_process(data, &keys, iv, state, out);
            }
            return;
        }
    }

    ctr256_process_fallback(data, key, iv, state, out);
}

/// In-place variant for zero-allocation stream processing with automatic hardware acceleration
#[inline(always)]
pub fn ctr256_process_inplace(
    data: &mut [u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut [u8],
) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") {
            unsafe {
                let keys = ni::expand_enc_key_256(key);
                ni::ctr256_process_inplace(data, &keys, iv, state);
            }
            return;
        }
    }

    ctr256_process_inplace_fallback(data, key, iv, state);
}

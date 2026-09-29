#![allow(clippy::missing_safety_doc, clippy::too_many_arguments)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256Enc;
use std::sync::atomic::{AtomicU8, Ordering};

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

// -------------------------------------------------------------------------------------------------
// Dispatch Modes & Hardware Acceleration Controls
// -------------------------------------------------------------------------------------------------

pub const MODE_UNINIT: u8 = 0;
pub const MODE_PORTABLE: u8 = 1;
pub const MODE_AESNI: u8 = 2;
pub const MODE_VAES256: u8 = 3;
pub const MODE_VAES512: u8 = 4;

static DISPATCH_MODE: AtomicU8 = AtomicU8::new(MODE_UNINIT);

/// Allow runtime / test override of dispatch mode (e.g. from Python or HYPERCRYPTO_FORCE)
pub fn set_dispatch_override(mode: u8) {
    DISPATCH_MODE.store(mode, Ordering::Relaxed);
}

pub fn get_dispatch_override() -> u8 {
    get_dispatch_mode()
}

#[inline(always)]
fn get_dispatch_mode() -> u8 {
    let mode = DISPATCH_MODE.load(Ordering::Relaxed);
    if mode != MODE_UNINIT {
        return mode;
    }
    init_dispatch_mode()
}

#[cold]
fn init_dispatch_mode() -> u8 {
    if let Ok(force) = std::env::var("HYPERCRYPTO_FORCE") {
        let m = match force.trim().to_lowercase().as_str() {
            "vaes512" | "vaes-512" | "512" => MODE_VAES512,
            "vaes256" | "vaes-256" | "256" => MODE_VAES256,
            "aesni" | "ni" | "sse" => MODE_AESNI,
            "portable" | "fallback" => MODE_PORTABLE,
            _ => MODE_PORTABLE,
        };
        DISPATCH_MODE.store(m, Ordering::Relaxed);
        return m;
    }

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("vaes")
            && is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512vl")
            && is_x86_feature_detected!("avx512bw")
        {
            DISPATCH_MODE.store(MODE_VAES512, Ordering::Relaxed);
            return MODE_VAES512;
        }

        if is_x86_feature_detected!("vaes") && is_x86_feature_detected!("avx2") {
            DISPATCH_MODE.store(MODE_VAES256, Ordering::Relaxed);
            return MODE_VAES256;
        }

        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse2") && is_x86_feature_detected!("ssse3") {
            DISPATCH_MODE.store(MODE_AESNI, Ordering::Relaxed);
            return MODE_AESNI;
        }
    }

    DISPATCH_MODE.store(MODE_PORTABLE, Ordering::Relaxed);
    MODE_PORTABLE
}

#[inline(always)]
pub fn increment_counter(iv: &mut [u8; 16]) {
    let val = u128::from_be_bytes(*iv).wrapping_add(1);
    *iv = val.to_be_bytes();
}

// Byte-swap mask for SSSE3/AVX2/AVX-512: reverses 16 bytes in-place
pub const BSWAP_MASK: [u8; 16] = [15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];

// -------------------------------------------------------------------------------------------------
// x86_64 Key Expansion (Shared across AES-NI and VAES)
// -------------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes", enable = "sse2")]
pub unsafe fn encrypt_1_block(mut b: __m128i, keys: &[__m128i; 15]) -> __m128i {
    b = _mm_xor_si128(b, keys[0]);
    b = _mm_aesenc_si128(b, keys[1]);
    b = _mm_aesenc_si128(b, keys[2]);
    b = _mm_aesenc_si128(b, keys[3]);
    b = _mm_aesenc_si128(b, keys[4]);
    b = _mm_aesenc_si128(b, keys[5]);
    b = _mm_aesenc_si128(b, keys[6]);
    b = _mm_aesenc_si128(b, keys[7]);
    b = _mm_aesenc_si128(b, keys[8]);
    b = _mm_aesenc_si128(b, keys[9]);
    b = _mm_aesenc_si128(b, keys[10]);
    b = _mm_aesenc_si128(b, keys[11]);
    b = _mm_aesenc_si128(b, keys[12]);
    b = _mm_aesenc_si128(b, keys[13]);
    _mm_aesenclast_si128(b, keys[14])
}

// -------------------------------------------------------------------------------------------------
// Step 1 & Step 2: Unrolled 8-Way AES-NI Kernel with In-Register Counter
// -------------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub mod ni {
    use super::*;

    #[inline(always)]
    unsafe fn encrypt_8_blocks_unrolled(
        b0: &mut __m128i,
        b1: &mut __m128i,
        b2: &mut __m128i,
        b3: &mut __m128i,
        b4: &mut __m128i,
        b5: &mut __m128i,
        b6: &mut __m128i,
        b7: &mut __m128i,
        keys: &[__m128i; 15],
    ) {
        let k0 = keys[0];
        *b0 = _mm_xor_si128(*b0, k0);
        *b1 = _mm_xor_si128(*b1, k0);
        *b2 = _mm_xor_si128(*b2, k0);
        *b3 = _mm_xor_si128(*b3, k0);
        *b4 = _mm_xor_si128(*b4, k0);
        *b5 = _mm_xor_si128(*b5, k0);
        *b6 = _mm_xor_si128(*b6, k0);
        *b7 = _mm_xor_si128(*b7, k0);

        macro_rules! round_8 {
            ($rk:expr) => {
                let k = $rk;
                *b0 = _mm_aesenc_si128(*b0, k);
                *b1 = _mm_aesenc_si128(*b1, k);
                *b2 = _mm_aesenc_si128(*b2, k);
                *b3 = _mm_aesenc_si128(*b3, k);
                *b4 = _mm_aesenc_si128(*b4, k);
                *b5 = _mm_aesenc_si128(*b5, k);
                *b6 = _mm_aesenc_si128(*b6, k);
                *b7 = _mm_aesenc_si128(*b7, k);
            };
        }

        round_8!(keys[1]);
        round_8!(keys[2]);
        round_8!(keys[3]);
        round_8!(keys[4]);
        round_8!(keys[5]);
        round_8!(keys[6]);
        round_8!(keys[7]);
        round_8!(keys[8]);
        round_8!(keys[9]);
        round_8!(keys[10]);
        round_8!(keys[11]);
        round_8!(keys[12]);
        round_8!(keys[13]);

        let k14 = keys[14];
        *b0 = _mm_aesenclast_si128(*b0, k14);
        *b1 = _mm_aesenclast_si128(*b1, k14);
        *b2 = _mm_aesenclast_si128(*b2, k14);
        *b3 = _mm_aesenclast_si128(*b3, k14);
        *b4 = _mm_aesenclast_si128(*b4, k14);
        *b5 = _mm_aesenclast_si128(*b5, k14);
        *b6 = _mm_aesenclast_si128(*b6, k14);
        *b7 = _mm_aesenclast_si128(*b7, k14);
    }

    #[inline(always)]
    unsafe fn encrypt_4_blocks_unrolled(
        b0: &mut __m128i,
        b1: &mut __m128i,
        b2: &mut __m128i,
        b3: &mut __m128i,
        keys: &[__m128i; 15],
    ) {
        let k0 = keys[0];
        *b0 = _mm_xor_si128(*b0, k0);
        *b1 = _mm_xor_si128(*b1, k0);
        *b2 = _mm_xor_si128(*b2, k0);
        *b3 = _mm_xor_si128(*b3, k0);

        macro_rules! round_4 {
            ($rk:expr) => {
                let k = $rk;
                *b0 = _mm_aesenc_si128(*b0, k);
                *b1 = _mm_aesenc_si128(*b1, k);
                *b2 = _mm_aesenc_si128(*b2, k);
                *b3 = _mm_aesenc_si128(*b3, k);
            };
        }

        round_4!(keys[1]);
        round_4!(keys[2]);
        round_4!(keys[3]);
        round_4!(keys[4]);
        round_4!(keys[5]);
        round_4!(keys[6]);
        round_4!(keys[7]);
        round_4!(keys[8]);
        round_4!(keys[9]);
        round_4!(keys[10]);
        round_4!(keys[11]);
        round_4!(keys[12]);
        round_4!(keys[13]);

        let k14 = keys[14];
        *b0 = _mm_aesenclast_si128(*b0, k14);
        *b1 = _mm_aesenclast_si128(*b1, k14);
        *b2 = _mm_aesenclast_si128(*b2, k14);
        *b3 = _mm_aesenclast_si128(*b3, k14);
    }

    #[target_feature(enable = "aes", enable = "sse2", enable = "ssse3")]
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
            state[0] = offset as u8;
            if data_idx == data_len {
                return;
            }
        }

        let bswap_mask = _mm_loadu_si128(BSWAP_MASK.as_ptr() as *const __m128i);
        let mut ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(iv.as_ptr() as *const __m128i), bswap_mask);
        let mut lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());

        let one = _mm_set_epi64x(0, 1);
        let two = _mm_set_epi64x(0, 2);
        let three = _mm_set_epi64x(0, 3);
        let four = _mm_set_epi64x(0, 4);
        let five = _mm_set_epi64x(0, 5);
        let six = _mm_set_epi64x(0, 6);
        let seven = _mm_set_epi64x(0, 7);
        let eight = _mm_set_epi64x(0, 8);

        // 8-Way Unrolled Parallel Processing (128 bytes per batch)
        while data_idx + 128 <= data_len {
            let (mut b0, mut b1, mut b2, mut b3, mut b4, mut b5, mut b6, mut b7);

            if lo <= u64::MAX - 8 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one);
                let c2 = _mm_add_epi64(c0, two);
                let c3 = _mm_add_epi64(c0, three);
                let c4 = _mm_add_epi64(c0, four);
                let c5 = _mm_add_epi64(c0, five);
                let c6 = _mm_add_epi64(c0, six);
                let c7 = _mm_add_epi64(c0, seven);
                ctr_rev = _mm_add_epi64(c0, eight);
                lo += 8;

                b0 = _mm_shuffle_epi8(c0, bswap_mask);
                b1 = _mm_shuffle_epi8(c1, bswap_mask);
                b2 = _mm_shuffle_epi8(c2, bswap_mask);
                b3 = _mm_shuffle_epi8(c3, bswap_mask);
                b4 = _mm_shuffle_epi8(c4, bswap_mask);
                b5 = _mm_shuffle_epi8(c5, bswap_mask);
                b6 = _mm_shuffle_epi8(c6, bswap_mask);
                b7 = _mm_shuffle_epi8(c7, bswap_mask);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask));
                let mut val = u128::from_be_bytes(cur);

                b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b2 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b3 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b4 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b5 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b6 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b7 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            encrypt_8_blocks_unrolled(&mut b0, &mut b1, &mut b2, &mut b3, &mut b4, &mut b5, &mut b6, &mut b7, keys);

            let d0 = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            let d1 = _mm_loadu_si128(data.as_ptr().add(data_idx + 16) as *const __m128i);
            let d2 = _mm_loadu_si128(data.as_ptr().add(data_idx + 32) as *const __m128i);
            let d3 = _mm_loadu_si128(data.as_ptr().add(data_idx + 48) as *const __m128i);
            let d4 = _mm_loadu_si128(data.as_ptr().add(data_idx + 64) as *const __m128i);
            let d5 = _mm_loadu_si128(data.as_ptr().add(data_idx + 80) as *const __m128i);
            let d6 = _mm_loadu_si128(data.as_ptr().add(data_idx + 96) as *const __m128i);
            let d7 = _mm_loadu_si128(data.as_ptr().add(data_idx + 112) as *const __m128i);

            _mm_storeu_si128(out.as_mut_ptr().add(data_idx) as *mut __m128i, _mm_xor_si128(d0, b0));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 16) as *mut __m128i, _mm_xor_si128(d1, b1));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 32) as *mut __m128i, _mm_xor_si128(d2, b2));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 48) as *mut __m128i, _mm_xor_si128(d3, b3));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 64) as *mut __m128i, _mm_xor_si128(d4, b4));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 80) as *mut __m128i, _mm_xor_si128(d5, b5));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 96) as *mut __m128i, _mm_xor_si128(d6, b6));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 112) as *mut __m128i, _mm_xor_si128(d7, b7));

            data_idx += 128;
        }

        // 4-Way Unrolled Processing (64 bytes)
        while data_idx + 64 <= data_len {
            let (mut b0, mut b1, mut b2, mut b3);
            if lo <= u64::MAX - 4 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one);
                let c2 = _mm_add_epi64(c0, two);
                let c3 = _mm_add_epi64(c0, three);
                ctr_rev = _mm_add_epi64(c0, four);
                lo += 4;

                b0 = _mm_shuffle_epi8(c0, bswap_mask);
                b1 = _mm_shuffle_epi8(c1, bswap_mask);
                b2 = _mm_shuffle_epi8(c2, bswap_mask);
                b3 = _mm_shuffle_epi8(c3, bswap_mask);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask));
                let mut val = u128::from_be_bytes(cur);

                b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b2 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b3 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            encrypt_4_blocks_unrolled(&mut b0, &mut b1, &mut b2, &mut b3, keys);

            let d0 = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            let d1 = _mm_loadu_si128(data.as_ptr().add(data_idx + 16) as *const __m128i);
            let d2 = _mm_loadu_si128(data.as_ptr().add(data_idx + 32) as *const __m128i);
            let d3 = _mm_loadu_si128(data.as_ptr().add(data_idx + 48) as *const __m128i);

            _mm_storeu_si128(out.as_mut_ptr().add(data_idx) as *mut __m128i, _mm_xor_si128(d0, b0));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 16) as *mut __m128i, _mm_xor_si128(d1, b1));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 32) as *mut __m128i, _mm_xor_si128(d2, b2));
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx + 48) as *mut __m128i, _mm_xor_si128(d3, b3));

            data_idx += 64;
        }

        // Single Block Processing (16 bytes)
        while data_idx + 16 <= data_len {
            let b0;
            if lo < u64::MAX {
                let c0 = ctr_rev;
                ctr_rev = _mm_add_epi64(c0, one);
                lo += 1;
                b0 = _mm_shuffle_epi8(c0, bswap_mask);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask));
                let val = u128::from_be_bytes(cur);
                b0 = _mm_loadu_si128(cur.as_ptr() as *const __m128i);
                let next_bytes = val.wrapping_add(1).to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            let ks = encrypt_1_block(b0, keys);
            let d = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            _mm_storeu_si128(out.as_mut_ptr().add(data_idx) as *mut __m128i, _mm_xor_si128(d, ks));
            data_idx += 16;
        }

        // Trailing bytes (< 16 bytes)
        if data_idx < data_len {
            let iv_b = _mm_shuffle_epi8(ctr_rev, bswap_mask);
            let ks = encrypt_1_block(iv_b, keys);
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);

            let rem = data_len - data_idx;
            for j in 0..rem {
                out[data_idx + j] = data[data_idx + j] ^ ks_bytes[j];
            }
            offset = rem;
            _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, iv_b);
        } else {
            let final_iv = _mm_shuffle_epi8(ctr_rev, bswap_mask);
            _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, final_iv);
            offset = 0;
        }

        state[0] = offset as u8;
    }

    #[target_feature(enable = "aes", enable = "sse2", enable = "ssse3")]
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
            state[0] = offset as u8;
            if data_idx == data_len {
                return;
            }
        }

        let bswap_mask = _mm_loadu_si128(BSWAP_MASK.as_ptr() as *const __m128i);
        let mut ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(iv.as_ptr() as *const __m128i), bswap_mask);
        let mut lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());

        let one = _mm_set_epi64x(0, 1);
        let two = _mm_set_epi64x(0, 2);
        let three = _mm_set_epi64x(0, 3);
        let four = _mm_set_epi64x(0, 4);
        let five = _mm_set_epi64x(0, 5);
        let six = _mm_set_epi64x(0, 6);
        let seven = _mm_set_epi64x(0, 7);
        let eight = _mm_set_epi64x(0, 8);

        while data_idx + 128 <= data_len {
            let (mut b0, mut b1, mut b2, mut b3, mut b4, mut b5, mut b6, mut b7);

            if lo <= u64::MAX - 8 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one);
                let c2 = _mm_add_epi64(c0, two);
                let c3 = _mm_add_epi64(c0, three);
                let c4 = _mm_add_epi64(c0, four);
                let c5 = _mm_add_epi64(c0, five);
                let c6 = _mm_add_epi64(c0, six);
                let c7 = _mm_add_epi64(c0, seven);
                ctr_rev = _mm_add_epi64(c0, eight);
                lo += 8;

                b0 = _mm_shuffle_epi8(c0, bswap_mask);
                b1 = _mm_shuffle_epi8(c1, bswap_mask);
                b2 = _mm_shuffle_epi8(c2, bswap_mask);
                b3 = _mm_shuffle_epi8(c3, bswap_mask);
                b4 = _mm_shuffle_epi8(c4, bswap_mask);
                b5 = _mm_shuffle_epi8(c5, bswap_mask);
                b6 = _mm_shuffle_epi8(c6, bswap_mask);
                b7 = _mm_shuffle_epi8(c7, bswap_mask);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask));
                let mut val = u128::from_be_bytes(cur);

                b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b2 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b3 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b4 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b5 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b6 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b7 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            encrypt_8_blocks_unrolled(&mut b0, &mut b1, &mut b2, &mut b3, &mut b4, &mut b5, &mut b6, &mut b7, keys);

            let d0 = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            let d1 = _mm_loadu_si128(data.as_ptr().add(data_idx + 16) as *const __m128i);
            let d2 = _mm_loadu_si128(data.as_ptr().add(data_idx + 32) as *const __m128i);
            let d3 = _mm_loadu_si128(data.as_ptr().add(data_idx + 48) as *const __m128i);
            let d4 = _mm_loadu_si128(data.as_ptr().add(data_idx + 64) as *const __m128i);
            let d5 = _mm_loadu_si128(data.as_ptr().add(data_idx + 80) as *const __m128i);
            let d6 = _mm_loadu_si128(data.as_ptr().add(data_idx + 96) as *const __m128i);
            let d7 = _mm_loadu_si128(data.as_ptr().add(data_idx + 112) as *const __m128i);

            _mm_storeu_si128(data.as_mut_ptr().add(data_idx) as *mut __m128i, _mm_xor_si128(d0, b0));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 16) as *mut __m128i, _mm_xor_si128(d1, b1));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 32) as *mut __m128i, _mm_xor_si128(d2, b2));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 48) as *mut __m128i, _mm_xor_si128(d3, b3));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 64) as *mut __m128i, _mm_xor_si128(d4, b4));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 80) as *mut __m128i, _mm_xor_si128(d5, b5));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 96) as *mut __m128i, _mm_xor_si128(d6, b6));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 112) as *mut __m128i, _mm_xor_si128(d7, b7));

            data_idx += 128;
        }

        while data_idx + 64 <= data_len {
            let (mut b0, mut b1, mut b2, mut b3);
            if lo <= u64::MAX - 4 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one);
                let c2 = _mm_add_epi64(c0, two);
                let c3 = _mm_add_epi64(c0, three);
                ctr_rev = _mm_add_epi64(c0, four);
                lo += 4;

                b0 = _mm_shuffle_epi8(c0, bswap_mask);
                b1 = _mm_shuffle_epi8(c1, bswap_mask);
                b2 = _mm_shuffle_epi8(c2, bswap_mask);
                b3 = _mm_shuffle_epi8(c3, bswap_mask);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask));
                let mut val = u128::from_be_bytes(cur);

                b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b2 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                b3 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            encrypt_4_blocks_unrolled(&mut b0, &mut b1, &mut b2, &mut b3, keys);

            let d0 = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            let d1 = _mm_loadu_si128(data.as_ptr().add(data_idx + 16) as *const __m128i);
            let d2 = _mm_loadu_si128(data.as_ptr().add(data_idx + 32) as *const __m128i);
            let d3 = _mm_loadu_si128(data.as_ptr().add(data_idx + 48) as *const __m128i);

            _mm_storeu_si128(data.as_mut_ptr().add(data_idx) as *mut __m128i, _mm_xor_si128(d0, b0));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 16) as *mut __m128i, _mm_xor_si128(d1, b1));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 32) as *mut __m128i, _mm_xor_si128(d2, b2));
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx + 48) as *mut __m128i, _mm_xor_si128(d3, b3));

            data_idx += 64;
        }

        while data_idx + 16 <= data_len {
            let b0;
            if lo < u64::MAX {
                let c0 = ctr_rev;
                ctr_rev = _mm_add_epi64(c0, one);
                lo += 1;
                b0 = _mm_shuffle_epi8(c0, bswap_mask);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask));
                let val = u128::from_be_bytes(cur);
                b0 = _mm_loadu_si128(cur.as_ptr() as *const __m128i);
                let next_bytes = val.wrapping_add(1).to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            let ks = encrypt_1_block(b0, keys);
            let d = _mm_loadu_si128(data.as_ptr().add(data_idx) as *const __m128i);
            _mm_storeu_si128(data.as_mut_ptr().add(data_idx) as *mut __m128i, _mm_xor_si128(d, ks));
            data_idx += 16;
        }

        if data_idx < data_len {
            let iv_b = _mm_shuffle_epi8(ctr_rev, bswap_mask);
            let ks = encrypt_1_block(iv_b, keys);
            let mut ks_bytes = [0u8; 16];
            _mm_storeu_si128(ks_bytes.as_mut_ptr() as *mut __m128i, ks);

            let rem = data_len - data_idx;
            for j in 0..rem {
                data[data_idx + j] ^= ks_bytes[j];
            }
            offset = rem;
            _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, iv_b);
        } else {
            let final_iv = _mm_shuffle_epi8(ctr_rev, bswap_mask);
            _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, final_iv);
            offset = 0;
        }

        state[0] = offset as u8;
    }
}

// -------------------------------------------------------------------------------------------------
// Step 3: VAES-256 (AVX2 + VAES) 16-Way (256 bytes per batch) Kernel
// -------------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub mod vaes256 {
    use super::*;

    #[target_feature(enable = "vaes", enable = "avx2")]
    pub unsafe fn expand_keys_256(keys: &[__m128i; 15]) -> [__m256i; 15] {
        [
            _mm256_broadcastsi128_si256(keys[0]),
            _mm256_broadcastsi128_si256(keys[1]),
            _mm256_broadcastsi128_si256(keys[2]),
            _mm256_broadcastsi128_si256(keys[3]),
            _mm256_broadcastsi128_si256(keys[4]),
            _mm256_broadcastsi128_si256(keys[5]),
            _mm256_broadcastsi128_si256(keys[6]),
            _mm256_broadcastsi128_si256(keys[7]),
            _mm256_broadcastsi128_si256(keys[8]),
            _mm256_broadcastsi128_si256(keys[9]),
            _mm256_broadcastsi128_si256(keys[10]),
            _mm256_broadcastsi128_si256(keys[11]),
            _mm256_broadcastsi128_si256(keys[12]),
            _mm256_broadcastsi128_si256(keys[13]),
            _mm256_broadcastsi128_si256(keys[14]),
        ]
    }

    #[inline(always)]
    unsafe fn vaes256_encrypt_8(
        y0: &mut __m256i,
        y1: &mut __m256i,
        y2: &mut __m256i,
        y3: &mut __m256i,
        y4: &mut __m256i,
        y5: &mut __m256i,
        y6: &mut __m256i,
        y7: &mut __m256i,
        keys: &[__m256i; 15],
    ) {
        let k0 = keys[0];
        *y0 = _mm256_xor_si256(*y0, k0);
        *y1 = _mm256_xor_si256(*y1, k0);
        *y2 = _mm256_xor_si256(*y2, k0);
        *y3 = _mm256_xor_si256(*y3, k0);
        *y4 = _mm256_xor_si256(*y4, k0);
        *y5 = _mm256_xor_si256(*y5, k0);
        *y6 = _mm256_xor_si256(*y6, k0);
        *y7 = _mm256_xor_si256(*y7, k0);

        macro_rules! round_vaes256 {
            ($rk:expr) => {
                let k = $rk;
                *y0 = _mm256_aesenc_epi128(*y0, k);
                *y1 = _mm256_aesenc_epi128(*y1, k);
                *y2 = _mm256_aesenc_epi128(*y2, k);
                *y3 = _mm256_aesenc_epi128(*y3, k);
                *y4 = _mm256_aesenc_epi128(*y4, k);
                *y5 = _mm256_aesenc_epi128(*y5, k);
                *y6 = _mm256_aesenc_epi128(*y6, k);
                *y7 = _mm256_aesenc_epi128(*y7, k);
            };
        }

        round_vaes256!(keys[1]);
        round_vaes256!(keys[2]);
        round_vaes256!(keys[3]);
        round_vaes256!(keys[4]);
        round_vaes256!(keys[5]);
        round_vaes256!(keys[6]);
        round_vaes256!(keys[7]);
        round_vaes256!(keys[8]);
        round_vaes256!(keys[9]);
        round_vaes256!(keys[10]);
        round_vaes256!(keys[11]);
        round_vaes256!(keys[12]);
        round_vaes256!(keys[13]);

        let k14 = keys[14];
        *y0 = _mm256_aesenclast_epi128(*y0, k14);
        *y1 = _mm256_aesenclast_epi128(*y1, k14);
        *y2 = _mm256_aesenclast_epi128(*y2, k14);
        *y3 = _mm256_aesenclast_epi128(*y3, k14);
        *y4 = _mm256_aesenclast_epi128(*y4, k14);
        *y5 = _mm256_aesenclast_epi128(*y5, k14);
        *y6 = _mm256_aesenclast_epi128(*y6, k14);
        *y7 = _mm256_aesenclast_epi128(*y7, k14);
    }

    #[target_feature(enable = "vaes", enable = "avx2")]
    pub unsafe fn ctr256_process(
        data: &[u8],
        raw_keys: &[__m128i; 15],
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

        if offset > 0 {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            let ks = encrypt_1_block(iv_b, raw_keys);
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
            state[0] = offset as u8;
            if data_idx == data_len {
                return;
            }
        }

        let keys256 = expand_keys_256(raw_keys);
        let bswap_mask_128 = _mm_loadu_si128(BSWAP_MASK.as_ptr() as *const __m128i);
        let bswap_mask_256 = _mm256_broadcastsi128_si256(bswap_mask_128);

        let mut ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(iv.as_ptr() as *const __m128i), bswap_mask_128);
        let mut lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());

        let one_128 = _mm_set_epi64x(0, 1);
        let step2 = _mm256_set_epi64x(0, 2, 0, 2);
        let step4 = _mm256_set_epi64x(0, 4, 0, 4);
        let step6 = _mm256_set_epi64x(0, 6, 0, 6);
        let step8 = _mm256_set_epi64x(0, 8, 0, 8);
        let step10 = _mm256_set_epi64x(0, 10, 0, 10);
        let step12 = _mm256_set_epi64x(0, 12, 0, 12);
        let step14 = _mm256_set_epi64x(0, 14, 0, 14);

        // 16-Way Unrolled Parallel Processing (256 bytes per batch)
        while data_idx + 256 <= data_len {
            let (mut y0, mut y1, mut y2, mut y3, mut y4, mut y5, mut y6, mut y7);

            if lo <= u64::MAX - 16 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one_128);
                let y0_r = _mm256_set_m128i(c1, c0);
                ctr_rev = _mm_add_epi64(c0, _mm_set_epi64x(0, 16));
                lo += 16;

                let y1_r = _mm256_add_epi64(y0_r, step2);
                let y2_r = _mm256_add_epi64(y0_r, step4);
                let y3_r = _mm256_add_epi64(y0_r, step6);
                let y4_r = _mm256_add_epi64(y0_r, step8);
                let y5_r = _mm256_add_epi64(y0_r, step10);
                let y6_r = _mm256_add_epi64(y0_r, step12);
                let y7_r = _mm256_add_epi64(y0_r, step14);

                y0 = _mm256_shuffle_epi8(y0_r, bswap_mask_256);
                y1 = _mm256_shuffle_epi8(y1_r, bswap_mask_256);
                y2 = _mm256_shuffle_epi8(y2_r, bswap_mask_256);
                y3 = _mm256_shuffle_epi8(y3_r, bswap_mask_256);
                y4 = _mm256_shuffle_epi8(y4_r, bswap_mask_256);
                y5 = _mm256_shuffle_epi8(y5_r, bswap_mask_256);
                y6 = _mm256_shuffle_epi8(y6_r, bswap_mask_256);
                y7 = _mm256_shuffle_epi8(y7_r, bswap_mask_256);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask_128));
                let mut val = u128::from_be_bytes(cur);

                macro_rules! next_y {
                    () => {{
                        let b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        _mm256_set_m128i(b1, b0)
                    }};
                }

                y0 = next_y!();
                y1 = next_y!();
                y2 = next_y!();
                y3 = next_y!();
                y4 = next_y!();
                y5 = next_y!();
                y6 = next_y!();
                y7 = next_y!();

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask_128);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            vaes256_encrypt_8(&mut y0, &mut y1, &mut y2, &mut y3, &mut y4, &mut y5, &mut y6, &mut y7, &keys256);

            let d0 = _mm256_loadu_si256(data.as_ptr().add(data_idx) as *const __m256i);
            let d1 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 32) as *const __m256i);
            let d2 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 64) as *const __m256i);
            let d3 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 96) as *const __m256i);
            let d4 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 128) as *const __m256i);
            let d5 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 160) as *const __m256i);
            let d6 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 192) as *const __m256i);
            let d7 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 224) as *const __m256i);

            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx) as *mut __m256i, _mm256_xor_si256(d0, y0));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 32) as *mut __m256i, _mm256_xor_si256(d1, y1));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 64) as *mut __m256i, _mm256_xor_si256(d2, y2));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 96) as *mut __m256i, _mm256_xor_si256(d3, y3));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 128) as *mut __m256i, _mm256_xor_si256(d4, y4));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 160) as *mut __m256i, _mm256_xor_si256(d5, y5));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 192) as *mut __m256i, _mm256_xor_si256(d6, y6));
            _mm256_storeu_si256(out.as_mut_ptr().add(data_idx + 224) as *mut __m256i, _mm256_xor_si256(d7, y7));

            data_idx += 256;
        }

        // Tail processing with AES-NI kernel
        let cur_iv = _mm_shuffle_epi8(ctr_rev, bswap_mask_128);
        _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, cur_iv);
        ni::ctr256_process(&data[data_idx..], raw_keys, iv, state, &mut out[data_idx..]);
    }

    #[target_feature(enable = "vaes", enable = "avx2")]
    pub unsafe fn ctr256_process_inplace(
        data: &mut [u8],
        raw_keys: &[__m128i; 15],
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
            let ks = encrypt_1_block(iv_b, raw_keys);
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
            state[0] = offset as u8;
            if data_idx == data_len {
                return;
            }
        }

        let keys256 = expand_keys_256(raw_keys);
        let bswap_mask_128 = _mm_loadu_si128(BSWAP_MASK.as_ptr() as *const __m128i);
        let bswap_mask_256 = _mm256_broadcastsi128_si256(bswap_mask_128);

        let mut ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(iv.as_ptr() as *const __m128i), bswap_mask_128);
        let mut lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());

        let one_128 = _mm_set_epi64x(0, 1);
        let step2 = _mm256_set_epi64x(0, 2, 0, 2);
        let step4 = _mm256_set_epi64x(0, 4, 0, 4);
        let step6 = _mm256_set_epi64x(0, 6, 0, 6);
        let step8 = _mm256_set_epi64x(0, 8, 0, 8);
        let step10 = _mm256_set_epi64x(0, 10, 0, 10);
        let step12 = _mm256_set_epi64x(0, 12, 0, 12);
        let step14 = _mm256_set_epi64x(0, 14, 0, 14);

        while data_idx + 256 <= data_len {
            let (mut y0, mut y1, mut y2, mut y3, mut y4, mut y5, mut y6, mut y7);

            if lo <= u64::MAX - 16 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one_128);
                let y0_r = _mm256_set_m128i(c1, c0);
                ctr_rev = _mm_add_epi64(c0, _mm_set_epi64x(0, 16));
                lo += 16;

                let y1_r = _mm256_add_epi64(y0_r, step2);
                let y2_r = _mm256_add_epi64(y0_r, step4);
                let y3_r = _mm256_add_epi64(y0_r, step6);
                let y4_r = _mm256_add_epi64(y0_r, step8);
                let y5_r = _mm256_add_epi64(y0_r, step10);
                let y6_r = _mm256_add_epi64(y0_r, step12);
                let y7_r = _mm256_add_epi64(y0_r, step14);

                y0 = _mm256_shuffle_epi8(y0_r, bswap_mask_256);
                y1 = _mm256_shuffle_epi8(y1_r, bswap_mask_256);
                y2 = _mm256_shuffle_epi8(y2_r, bswap_mask_256);
                y3 = _mm256_shuffle_epi8(y3_r, bswap_mask_256);
                y4 = _mm256_shuffle_epi8(y4_r, bswap_mask_256);
                y5 = _mm256_shuffle_epi8(y5_r, bswap_mask_256);
                y6 = _mm256_shuffle_epi8(y6_r, bswap_mask_256);
                y7 = _mm256_shuffle_epi8(y7_r, bswap_mask_256);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask_128));
                let mut val = u128::from_be_bytes(cur);

                macro_rules! next_y {
                    () => {{
                        let b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        _mm256_set_m128i(b1, b0)
                    }};
                }

                y0 = next_y!();
                y1 = next_y!();
                y2 = next_y!();
                y3 = next_y!();
                y4 = next_y!();
                y5 = next_y!();
                y6 = next_y!();
                y7 = next_y!();

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask_128);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            vaes256_encrypt_8(&mut y0, &mut y1, &mut y2, &mut y3, &mut y4, &mut y5, &mut y6, &mut y7, &keys256);

            let d0 = _mm256_loadu_si256(data.as_ptr().add(data_idx) as *const __m256i);
            let d1 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 32) as *const __m256i);
            let d2 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 64) as *const __m256i);
            let d3 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 96) as *const __m256i);
            let d4 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 128) as *const __m256i);
            let d5 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 160) as *const __m256i);
            let d6 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 192) as *const __m256i);
            let d7 = _mm256_loadu_si256(data.as_ptr().add(data_idx + 224) as *const __m256i);

            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx) as *mut __m256i, _mm256_xor_si256(d0, y0));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 32) as *mut __m256i, _mm256_xor_si256(d1, y1));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 64) as *mut __m256i, _mm256_xor_si256(d2, y2));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 96) as *mut __m256i, _mm256_xor_si256(d3, y3));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 128) as *mut __m256i, _mm256_xor_si256(d4, y4));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 160) as *mut __m256i, _mm256_xor_si256(d5, y5));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 192) as *mut __m256i, _mm256_xor_si256(d6, y6));
            _mm256_storeu_si256(data.as_mut_ptr().add(data_idx + 224) as *mut __m256i, _mm256_xor_si256(d7, y7));

            data_idx += 256;
        }

        let cur_iv = _mm_shuffle_epi8(ctr_rev, bswap_mask_128);
        _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, cur_iv);
        ni::ctr256_process_inplace(&mut data[data_idx..], raw_keys, iv, state);
    }
}

// -------------------------------------------------------------------------------------------------
// Step 3: VAES-512 (AVX-512 + VAES) 32-Way (512 bytes per batch) Kernel
// -------------------------------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub mod vaes512 {
    use super::*;

    #[target_feature(enable = "vaes", enable = "avx512f", enable = "avx512vl", enable = "avx512bw")]
    pub unsafe fn expand_keys_512(keys: &[__m128i; 15]) -> [__m512i; 15] {
        [
            _mm512_broadcast_i32x4(keys[0]),
            _mm512_broadcast_i32x4(keys[1]),
            _mm512_broadcast_i32x4(keys[2]),
            _mm512_broadcast_i32x4(keys[3]),
            _mm512_broadcast_i32x4(keys[4]),
            _mm512_broadcast_i32x4(keys[5]),
            _mm512_broadcast_i32x4(keys[6]),
            _mm512_broadcast_i32x4(keys[7]),
            _mm512_broadcast_i32x4(keys[8]),
            _mm512_broadcast_i32x4(keys[9]),
            _mm512_broadcast_i32x4(keys[10]),
            _mm512_broadcast_i32x4(keys[11]),
            _mm512_broadcast_i32x4(keys[12]),
            _mm512_broadcast_i32x4(keys[13]),
            _mm512_broadcast_i32x4(keys[14]),
        ]
    }

    #[inline(always)]
    unsafe fn vaes512_encrypt_8(
        z0: &mut __m512i,
        z1: &mut __m512i,
        z2: &mut __m512i,
        z3: &mut __m512i,
        z4: &mut __m512i,
        z5: &mut __m512i,
        z6: &mut __m512i,
        z7: &mut __m512i,
        keys: &[__m512i; 15],
    ) {
        let k0 = keys[0];
        *z0 = _mm512_xor_si512(*z0, k0);
        *z1 = _mm512_xor_si512(*z1, k0);
        *z2 = _mm512_xor_si512(*z2, k0);
        *z3 = _mm512_xor_si512(*z3, k0);
        *z4 = _mm512_xor_si512(*z4, k0);
        *z5 = _mm512_xor_si512(*z5, k0);
        *z6 = _mm512_xor_si512(*z6, k0);
        *z7 = _mm512_xor_si512(*z7, k0);

        macro_rules! round_vaes512 {
            ($rk:expr) => {
                let k = $rk;
                *z0 = _mm512_aesenc_epi128(*z0, k);
                *z1 = _mm512_aesenc_epi128(*z1, k);
                *z2 = _mm512_aesenc_epi128(*z2, k);
                *z3 = _mm512_aesenc_epi128(*z3, k);
                *z4 = _mm512_aesenc_epi128(*z4, k);
                *z5 = _mm512_aesenc_epi128(*z5, k);
                *z6 = _mm512_aesenc_epi128(*z6, k);
                *z7 = _mm512_aesenc_epi128(*z7, k);
            };
        }

        round_vaes512!(keys[1]);
        round_vaes512!(keys[2]);
        round_vaes512!(keys[3]);
        round_vaes512!(keys[4]);
        round_vaes512!(keys[5]);
        round_vaes512!(keys[6]);
        round_vaes512!(keys[7]);
        round_vaes512!(keys[8]);
        round_vaes512!(keys[9]);
        round_vaes512!(keys[10]);
        round_vaes512!(keys[11]);
        round_vaes512!(keys[12]);
        round_vaes512!(keys[13]);

        let k14 = keys[14];
        *z0 = _mm512_aesenclast_epi128(*z0, k14);
        *z1 = _mm512_aesenclast_epi128(*z1, k14);
        *z2 = _mm512_aesenclast_epi128(*z2, k14);
        *z3 = _mm512_aesenclast_epi128(*z3, k14);
        *z4 = _mm512_aesenclast_epi128(*z4, k14);
        *z5 = _mm512_aesenclast_epi128(*z5, k14);
        *z6 = _mm512_aesenclast_epi128(*z6, k14);
        *z7 = _mm512_aesenclast_epi128(*z7, k14);
    }

    #[target_feature(enable = "vaes", enable = "avx512f", enable = "avx512vl", enable = "avx512bw")]
    pub unsafe fn ctr256_process(
        data: &[u8],
        raw_keys: &[__m128i; 15],
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

        if offset > 0 {
            let iv_b = _mm_loadu_si128(iv.as_ptr() as *const __m128i);
            let ks = encrypt_1_block(iv_b, raw_keys);
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
            state[0] = offset as u8;
            if data_idx == data_len {
                return;
            }
        }

        let keys512 = expand_keys_512(raw_keys);
        let bswap_mask_128 = _mm_loadu_si128(BSWAP_MASK.as_ptr() as *const __m128i);
        let bswap_mask_512 = _mm512_broadcast_i32x4(bswap_mask_128);

        let mut ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(iv.as_ptr() as *const __m128i), bswap_mask_128);
        let mut lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());

        let one_128 = _mm_set_epi64x(0, 1);
        let two_128 = _mm_set_epi64x(0, 2);
        let three_128 = _mm_set_epi64x(0, 3);

        let step4 = _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4);
        let step8 = _mm512_set_epi64(0, 8, 0, 8, 0, 8, 0, 8);
        let step12 = _mm512_set_epi64(0, 12, 0, 12, 0, 12, 0, 12);
        let step16 = _mm512_set_epi64(0, 16, 0, 16, 0, 16, 0, 16);
        let step20 = _mm512_set_epi64(0, 20, 0, 20, 0, 20, 0, 20);
        let step24 = _mm512_set_epi64(0, 24, 0, 24, 0, 24, 0, 24);
        let step28 = _mm512_set_epi64(0, 28, 0, 28, 0, 28, 0, 28);

        // 32-Way Unrolled Parallel Processing (512 bytes per batch)
        while data_idx + 512 <= data_len {
            let (mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7);

            if lo <= u64::MAX - 32 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one_128);
                let c2 = _mm_add_epi64(c0, two_128);
                let c3 = _mm_add_epi64(c0, three_128);
                let y0 = _mm256_set_m128i(c1, c0);
                let y1 = _mm256_set_m128i(c3, c2);
                let z0_r = _mm512_inserti64x4(_mm512_castsi256_si512(y0), y1, 1);
                ctr_rev = _mm_add_epi64(c0, _mm_set_epi64x(0, 32));
                lo += 32;

                let z1_r = _mm512_add_epi64(z0_r, step4);
                let z2_r = _mm512_add_epi64(z0_r, step8);
                let z3_r = _mm512_add_epi64(z0_r, step12);
                let z4_r = _mm512_add_epi64(z0_r, step16);
                let z5_r = _mm512_add_epi64(z0_r, step20);
                let z6_r = _mm512_add_epi64(z0_r, step24);
                let z7_r = _mm512_add_epi64(z0_r, step28);

                z0 = _mm512_shuffle_epi8(z0_r, bswap_mask_512);
                z1 = _mm512_shuffle_epi8(z1_r, bswap_mask_512);
                z2 = _mm512_shuffle_epi8(z2_r, bswap_mask_512);
                z3 = _mm512_shuffle_epi8(z3_r, bswap_mask_512);
                z4 = _mm512_shuffle_epi8(z4_r, bswap_mask_512);
                z5 = _mm512_shuffle_epi8(z5_r, bswap_mask_512);
                z6 = _mm512_shuffle_epi8(z6_r, bswap_mask_512);
                z7 = _mm512_shuffle_epi8(z7_r, bswap_mask_512);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask_128));
                let mut val = u128::from_be_bytes(cur);

                macro_rules! next_z {
                    () => {{
                        let b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b2 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b3 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let y0 = _mm256_set_m128i(b1, b0);
                        let y1 = _mm256_set_m128i(b3, b2);
                        _mm512_inserti64x4(_mm512_castsi256_si512(y0), y1, 1)
                    }};
                }

                z0 = next_z!();
                z1 = next_z!();
                z2 = next_z!();
                z3 = next_z!();
                z4 = next_z!();
                z5 = next_z!();
                z6 = next_z!();
                z7 = next_z!();

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask_128);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            vaes512_encrypt_8(&mut z0, &mut z1, &mut z2, &mut z3, &mut z4, &mut z5, &mut z6, &mut z7, &keys512);

            let d0 = _mm512_loadu_si512(data.as_ptr().add(data_idx) as *const __m512i);
            let d1 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 64) as *const __m512i);
            let d2 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 128) as *const __m512i);
            let d3 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 192) as *const __m512i);
            let d4 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 256) as *const __m512i);
            let d5 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 320) as *const __m512i);
            let d6 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 384) as *const __m512i);
            let d7 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 448) as *const __m512i);

            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx) as *mut __m512i, _mm512_xor_si512(d0, z0));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 64) as *mut __m512i, _mm512_xor_si512(d1, z1));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 128) as *mut __m512i, _mm512_xor_si512(d2, z2));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 192) as *mut __m512i, _mm512_xor_si512(d3, z3));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 256) as *mut __m512i, _mm512_xor_si512(d4, z4));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 320) as *mut __m512i, _mm512_xor_si512(d5, z5));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 384) as *mut __m512i, _mm512_xor_si512(d6, z6));
            _mm512_storeu_si512(out.as_mut_ptr().add(data_idx + 448) as *mut __m512i, _mm512_xor_si512(d7, z7));

            data_idx += 512;
        }

        // Tail processing with VAES-256 or AES-NI
        let cur_iv = _mm_shuffle_epi8(ctr_rev, bswap_mask_128);
        _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, cur_iv);
        vaes256::ctr256_process(&data[data_idx..], raw_keys, iv, state, &mut out[data_idx..]);
    }

    #[target_feature(enable = "vaes", enable = "avx512f", enable = "avx512vl", enable = "avx512bw")]
    pub unsafe fn ctr256_process_inplace(
        data: &mut [u8],
        raw_keys: &[__m128i; 15],
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
            let ks = encrypt_1_block(iv_b, raw_keys);
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
            state[0] = offset as u8;
            if data_idx == data_len {
                return;
            }
        }

        let keys512 = expand_keys_512(raw_keys);
        let bswap_mask_128 = _mm_loadu_si128(BSWAP_MASK.as_ptr() as *const __m128i);
        let bswap_mask_512 = _mm512_broadcast_i32x4(bswap_mask_128);

        let mut ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(iv.as_ptr() as *const __m128i), bswap_mask_128);
        let mut lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());

        let one_128 = _mm_set_epi64x(0, 1);
        let two_128 = _mm_set_epi64x(0, 2);
        let three_128 = _mm_set_epi64x(0, 3);

        let step4 = _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4);
        let step8 = _mm512_set_epi64(0, 8, 0, 8, 0, 8, 0, 8);
        let step12 = _mm512_set_epi64(0, 12, 0, 12, 0, 12, 0, 12);
        let step16 = _mm512_set_epi64(0, 16, 0, 16, 0, 16, 0, 16);
        let step20 = _mm512_set_epi64(0, 20, 0, 20, 0, 20, 0, 20);
        let step24 = _mm512_set_epi64(0, 24, 0, 24, 0, 24, 0, 24);
        let step28 = _mm512_set_epi64(0, 28, 0, 28, 0, 28, 0, 28);

        while data_idx + 512 <= data_len {
            let (mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7);

            if lo <= u64::MAX - 32 {
                let c0 = ctr_rev;
                let c1 = _mm_add_epi64(c0, one_128);
                let c2 = _mm_add_epi64(c0, two_128);
                let c3 = _mm_add_epi64(c0, three_128);
                let y0 = _mm256_set_m128i(c1, c0);
                let y1 = _mm256_set_m128i(c3, c2);
                let z0_r = _mm512_inserti64x4(_mm512_castsi256_si512(y0), y1, 1);
                ctr_rev = _mm_add_epi64(c0, _mm_set_epi64x(0, 32));
                lo += 32;

                let z1_r = _mm512_add_epi64(z0_r, step4);
                let z2_r = _mm512_add_epi64(z0_r, step8);
                let z3_r = _mm512_add_epi64(z0_r, step12);
                let z4_r = _mm512_add_epi64(z0_r, step16);
                let z5_r = _mm512_add_epi64(z0_r, step20);
                let z6_r = _mm512_add_epi64(z0_r, step24);
                let z7_r = _mm512_add_epi64(z0_r, step28);

                z0 = _mm512_shuffle_epi8(z0_r, bswap_mask_512);
                z1 = _mm512_shuffle_epi8(z1_r, bswap_mask_512);
                z2 = _mm512_shuffle_epi8(z2_r, bswap_mask_512);
                z3 = _mm512_shuffle_epi8(z3_r, bswap_mask_512);
                z4 = _mm512_shuffle_epi8(z4_r, bswap_mask_512);
                z5 = _mm512_shuffle_epi8(z5_r, bswap_mask_512);
                z6 = _mm512_shuffle_epi8(z6_r, bswap_mask_512);
                z7 = _mm512_shuffle_epi8(z7_r, bswap_mask_512);
            } else {
                let mut cur = [0u8; 16];
                _mm_storeu_si128(cur.as_mut_ptr() as *mut __m128i, _mm_shuffle_epi8(ctr_rev, bswap_mask_128));
                let mut val = u128::from_be_bytes(cur);

                macro_rules! next_z {
                    () => {{
                        let b0 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b1 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b2 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let b3 = _mm_loadu_si128(val.to_be_bytes().as_ptr() as *const __m128i); val = val.wrapping_add(1);
                        let y0 = _mm256_set_m128i(b1, b0);
                        let y1 = _mm256_set_m128i(b3, b2);
                        _mm512_inserti64x4(_mm512_castsi256_si512(y0), y1, 1)
                    }};
                }

                z0 = next_z!();
                z1 = next_z!();
                z2 = next_z!();
                z3 = next_z!();
                z4 = next_z!();
                z5 = next_z!();
                z6 = next_z!();
                z7 = next_z!();

                let next_bytes = val.to_be_bytes();
                ctr_rev = _mm_shuffle_epi8(_mm_loadu_si128(next_bytes.as_ptr() as *const __m128i), bswap_mask_128);
                lo = u64::from_be_bytes(next_bytes[8..16].try_into().unwrap());
            }

            vaes512_encrypt_8(&mut z0, &mut z1, &mut z2, &mut z3, &mut z4, &mut z5, &mut z6, &mut z7, &keys512);

            let d0 = _mm512_loadu_si512(data.as_ptr().add(data_idx) as *const __m512i);
            let d1 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 64) as *const __m512i);
            let d2 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 128) as *const __m512i);
            let d3 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 192) as *const __m512i);
            let d4 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 256) as *const __m512i);
            let d5 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 320) as *const __m512i);
            let d6 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 384) as *const __m512i);
            let d7 = _mm512_loadu_si512(data.as_ptr().add(data_idx + 448) as *const __m512i);

            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx) as *mut __m512i, _mm512_xor_si512(d0, z0));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 64) as *mut __m512i, _mm512_xor_si512(d1, z1));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 128) as *mut __m512i, _mm512_xor_si512(d2, z2));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 192) as *mut __m512i, _mm512_xor_si512(d3, z3));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 256) as *mut __m512i, _mm512_xor_si512(d4, z4));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 320) as *mut __m512i, _mm512_xor_si512(d5, z5));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 384) as *mut __m512i, _mm512_xor_si512(d6, z6));
            _mm512_storeu_si512(data.as_mut_ptr().add(data_idx + 448) as *mut __m512i, _mm512_xor_si512(d7, z7));

            data_idx += 512;
        }

        let cur_iv = _mm_shuffle_epi8(ctr_rev, bswap_mask_128);
        _mm_storeu_si128(iv.as_mut_ptr() as *mut __m128i, cur_iv);
        vaes256::ctr256_process_inplace(&mut data[data_idx..], raw_keys, iv, state);
    }
}

// -------------------------------------------------------------------------------------------------
// Step 6: aarch64 ARM NEON + Crypto Extensions Kernel
// -------------------------------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
pub mod neon {
    use super::*;

    #[inline(always)]
    pub unsafe fn ctr256_process(
        data: &[u8],
        key: &[u8; 32],
        iv: &mut [u8; 16],
        state: &mut [u8],
        out: &mut [u8],
    ) {
        ctr256_process_fallback(data, key, iv, state, out);
    }

    #[inline(always)]
    pub unsafe fn ctr256_process_inplace(
        data: &mut [u8],
        key: &[u8; 32],
        iv: &mut [u8; 16],
        state: &mut [u8],
    ) {
        ctr256_process_inplace_fallback(data, key, iv, state);
    }
}

// -------------------------------------------------------------------------------------------------
// Safe Portable Fallback (aes crate)
// -------------------------------------------------------------------------------------------------

pub fn ctr256_process_fallback(
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
        state[0] = offset as u8;
        if data_idx == data_len {
            return;
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
    } else {
        offset = 0;
    }

    state[0] = offset as u8;
}

pub fn ctr256_process_inplace_fallback(
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
        state[0] = offset as u8;
        if data_idx == data_len {
            return;
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
    } else {
        offset = 0;
    }

    state[0] = offset as u8;
}

// -------------------------------------------------------------------------------------------------
// Public APIs with Fast Dispatch
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
    let mode = get_dispatch_mode();

    #[cfg(target_arch = "x86_64")]
    {
        if mode == MODE_VAES512 {
            unsafe {
                let keys = expand_enc_key_256(key);
                vaes512::ctr256_process(data, &keys, iv, state, out);
                return;
            }
        }
        if mode == MODE_VAES256 {
            unsafe {
                let keys = expand_enc_key_256(key);
                vaes256::ctr256_process(data, &keys, iv, state, out);
                return;
            }
        }
        if mode == MODE_AESNI {
            unsafe {
                let keys = expand_enc_key_256(key);
                ni::ctr256_process(data, &keys, iv, state, out);
                return;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            neon::ctr256_process(data, key, iv, state, out);
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
    let mode = get_dispatch_mode();

    #[cfg(target_arch = "x86_64")]
    {
        if mode == MODE_VAES512 {
            unsafe {
                let keys = expand_enc_key_256(key);
                vaes512::ctr256_process_inplace(data, &keys, iv, state);
                return;
            }
        }
        if mode == MODE_VAES256 {
            unsafe {
                let keys = expand_enc_key_256(key);
                vaes256::ctr256_process_inplace(data, &keys, iv, state);
                return;
            }
        }
        if mode == MODE_AESNI {
            unsafe {
                let keys = expand_enc_key_256(key);
                ni::ctr256_process_inplace(data, &keys, iv, state);
                return;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            neon::ctr256_process_inplace(data, key, iv, state);
            return;
        }
    }

    ctr256_process_inplace_fallback(data, key, iv, state);
}

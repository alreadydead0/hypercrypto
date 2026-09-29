use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

#[inline(always)]
pub fn increment_counter(iv: &mut [u8; 16]) {
    for byte in iv.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// High-throughput AES-256-CTR processor with 8-way parallel hardware unrolling,
/// in-place IV counter incrementation, and sub-block keystream state tracking.
#[inline(always)]
pub fn ctr256_process(
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

    let cipher = Aes256::new(GenericArray::from_slice(key));
    let mut offset = (state[0] & 0x0F) as usize;
    let mut data_idx = 0;

    // 1. Drain active partial block if offset != 0
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

    // 2. 8-Way Unrolled Parallel Block Processing (128 bytes at once)
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

    // 3. 4-Way Unrolled Processing (64 bytes at once)
    while data_idx + 64 <= data_len {
        let mut blocks = [GenericArray::<u8, aes::cipher::typenum::U16>::default(); 4];
        for i in 0..4 {
            blocks[i] = *GenericArray::from_slice(iv);
            increment_counter(iv);
        }

        cipher.encrypt_blocks(&mut blocks);

        for i in 0..4 {
            let chunk_in = &data[data_idx + i * 16..data_idx + (i + 1) * 16];
            let chunk_out = &mut out[data_idx + i * 16..data_idx + (i + 1) * 16];
            let ks = &blocks[i];
            for j in 0..16 {
                chunk_out[j] = chunk_in[j] ^ ks[j];
            }
        }
        data_idx += 64;
    }

    // 4. Single Block Processing (16 bytes)
    while data_idx + 16 <= data_len {
        let mut block = *GenericArray::from_slice(iv);
        increment_counter(iv);
        cipher.encrypt_block(&mut block);

        for j in 0..16 {
            out[data_idx + j] = data[data_idx + j] ^ block[j];
        }
        data_idx += 16;
    }

    // 5. Remaining trailing bytes (< 16 bytes)
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

/// In-place variant for zero-allocation stream processing
#[inline(always)]
pub fn ctr256_process_inplace(
    data: &mut [u8],
    key: &[u8; 32],
    iv: &mut [u8; 16],
    state: &mut [u8],
) {
    let data_len = data.len();
    if data_len == 0 {
        return;
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));
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

    while data_idx + 64 <= data_len {
        let mut blocks = [GenericArray::<u8, aes::cipher::typenum::U16>::default(); 4];
        for i in 0..4 {
            blocks[i] = *GenericArray::from_slice(iv);
            increment_counter(iv);
        }

        cipher.encrypt_blocks(&mut blocks);

        for i in 0..4 {
            let chunk = &mut data[data_idx + i * 16..data_idx + (i + 1) * 16];
            let ks = &blocks[i];
            for j in 0..16 {
                chunk[j] ^= ks[j];
            }
        }
        data_idx += 64;
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

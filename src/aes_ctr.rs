use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

pub struct Aes256CtrState {
    cipher: Aes256,
    counter: [u8; 16],
    keystream_buffer: [u8; 16],
    buffer_offset: usize,
}

impl Aes256CtrState {
    #[inline(always)]
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut counter = [0u8; 16];
        counter.copy_from_slice(iv);
        Self {
            cipher,
            counter,
            keystream_buffer: [0u8; 16],
            buffer_offset: 16,
        }
    }

    #[inline(always)]
    fn increment_counter(&mut self) {
        for byte in self.counter.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }

    #[inline(always)]
    pub fn process_inplace(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        let len = data.len();

        // 1. Drain remaining keystream bytes from previous block
        while self.buffer_offset < 16 && offset < len {
            data[offset] ^= self.keystream_buffer[self.buffer_offset];
            self.buffer_offset += 1;
            offset += 1;
        }

        // 2. 8-Way Unrolled Parallel AES-NI Block Processing (128 bytes at once)
        while offset + 128 <= len {
            let mut blocks = [GenericArray::<u8, aes::cipher::typenum::U16>::default(); 8];
            for i in 0..8 {
                blocks[i] = *GenericArray::from_slice(&self.counter);
                self.increment_counter();
            }

            self.cipher.encrypt_blocks(&mut blocks);

            for i in 0..8 {
                let chunk = &mut data[offset + i * 16..offset + (i + 1) * 16];
                let ks = &blocks[i];
                for j in 0..16 {
                    chunk[j] ^= ks[j];
                }
            }
            offset += 128;
        }

        // 3. 4-Way Unrolled Processing (64 bytes at once)
        while offset + 64 <= len {
            let mut blocks = [GenericArray::<u8, aes::cipher::typenum::U16>::default(); 4];
            for i in 0..4 {
                blocks[i] = *GenericArray::from_slice(&self.counter);
                self.increment_counter();
            }

            self.cipher.encrypt_blocks(&mut blocks);

            for i in 0..4 {
                let chunk = &mut data[offset + i * 16..offset + (i + 1) * 16];
                let ks = &blocks[i];
                for j in 0..16 {
                    chunk[j] ^= ks[j];
                }
            }
            offset += 64;
        }

        // 4. Single Block Processing (16 bytes)
        while offset + 16 <= len {
            let mut block = *GenericArray::from_slice(&self.counter);
            self.increment_counter();
            self.cipher.encrypt_block(&mut block);

            for j in 0..16 {
                data[offset + j] ^= block[j];
            }
            offset += 16;
        }

        // 5. Remaining trailing bytes (< 16 bytes)
        if offset < len {
            let mut block = *GenericArray::from_slice(&self.counter);
            self.increment_counter();
            self.cipher.encrypt_block(&mut block);
            self.keystream_buffer.copy_from_slice(&block);

            let remaining = len - offset;
            for j in 0..remaining {
                data[offset + j] ^= self.keystream_buffer[j];
            }
            self.buffer_offset = remaining;
        }
    }
}

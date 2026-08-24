use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

/// AES-256-IGE Encryption In-place
#[inline(always)]
pub fn ige256_encrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let chunks = data.chunks_exact_mut(16);
    for chunk in chunks {
        let p = <&mut [u8; 16]>::try_from(chunk).unwrap();
        let mut t = [0u8; 16];
        for i in 0..16 {
            t[i] = p[i] ^ iv1[i];
        }

        let mut block = *GenericArray::from_slice(&t);
        cipher.encrypt_block(&mut block);

        let mut c = [0u8; 16];
        for i in 0..16 {
            c[i] = block[i] ^ iv2[i];
        }

        iv1 = c;
        iv2 = *p;
        p.copy_from_slice(&c);
    }
}

/// AES-256-IGE Decryption In-place
#[inline(always)]
pub fn ige256_decrypt_inplace(data: &mut [u8], key: &[u8; 32], iv: &[u8; 32]) {
    debug_assert!(data.len() % 16 == 0);
    let cipher = Aes256::new(GenericArray::from_slice(key));

    let mut iv1: [u8; 16] = iv[0..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let chunks = data.chunks_exact_mut(16);
    for chunk in chunks {
        let c = <&mut [u8; 16]>::try_from(chunk).unwrap();
        let c_copy = *c;

        let mut t = [0u8; 16];
        for i in 0..16 {
            t[i] = c[i] ^ iv2[i];
        }

        let mut block = *GenericArray::from_slice(&t);
        cipher.decrypt_block(&mut block);

        let mut p = [0u8; 16];
        for i in 0..16 {
            p[i] = block[i] ^ iv1[i];
        }

        iv1 = c_copy;
        iv2 = p;
        c.copy_from_slice(&p);
    }
}

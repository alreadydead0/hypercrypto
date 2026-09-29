import os
import pytest
import hypercrypto as H
import tgcrypto as T

BOUNDARY_SIZES = [
    1, 15, 16, 17, 63, 64, 65, 127, 128, 129,
    255, 256, 257, 1000, 65535, 65536, 65537, 100001, 3 * 65536 + 123
]

def make_special_ivs():
    ivs = []
    # 1. Random IV
    ivs.append(("random", os.urandom(16)))
    # 2. Low byte 0xff
    iv_low_ff = bytearray(os.urandom(16))
    iv_low_ff[15] = 0xFF
    ivs.append(("low_byte_ff", bytes(iv_low_ff)))
    # 3. Low 8 bytes 0xff (near 64-bit carry)
    iv_low8_ff = bytearray(os.urandom(16))
    iv_low8_ff[8:16] = b"\xff" * 8
    ivs.append(("low_8_bytes_ff", bytes(iv_low8_ff)))
    # 4. Low u64 near overflow (e.g. 2^64 - 3)
    val = (int.from_bytes(os.urandom(8), "big") << 64) | (0xFFFFFFFFFFFFFFFF - 3)
    ivs.append(("low_u64_near_overflow", val.to_bytes(16, "big")))
    # 5. All 0xff (128-bit wrap to 0)
    ivs.append(("all_0xff", b"\xff" * 16))
    return ivs

# Available modes on this CPU
SUPPORTED_MODES = ["portable", "aesni"]

@pytest.mark.parametrize("mode", SUPPORTED_MODES)
@pytest.mark.parametrize("size", BOUNDARY_SIZES)
@pytest.mark.parametrize("iv_name,iv_bytes", make_special_ivs())
def test_ctr_dispatch_boundary_cases(mode, size, iv_name, iv_bytes):
    H._set_force_mode(mode)
    assert H._get_force_mode() == mode

    key = os.urandom(32)
    plaintext = os.urandom(size)

    # 1. Bytes API Encrypt
    iv_h = bytearray(iv_bytes)
    st_h = bytearray(1)
    iv_t = bytearray(iv_bytes)
    st_t = bytearray(1)

    ct_h = H.ctr256_encrypt(plaintext, key, iv_h, st_h)
    ct_t = T.ctr256_encrypt(plaintext, key, iv_t, st_t)

    assert ct_h == ct_t
    assert iv_h == iv_t
    assert st_h == st_t

    # 2. Bytes API Decrypt
    iv_h_dec = bytearray(iv_bytes)
    st_h_dec = bytearray(1)
    iv_t_dec = bytearray(iv_bytes)
    st_t_dec = bytearray(1)

    pt_h = H.ctr256_decrypt(ct_h, key, iv_h_dec, st_h_dec)
    pt_t = T.ctr256_decrypt(ct_t, key, iv_t_dec, st_t_dec)

    assert pt_h == plaintext
    assert pt_t == plaintext
    assert iv_h_dec == iv_t_dec
    assert st_h_dec == st_t_dec

    # 3. Inplace API Encrypt
    data_h = bytearray(plaintext)
    iv_h_in = bytearray(iv_bytes)
    st_h_in = bytearray(1)

    data_t = bytearray(plaintext)
    iv_t_in = bytearray(iv_bytes)
    st_t_in = bytearray(1)

    H.ctr256_encrypt_inplace(data_h, key, iv_h_in, st_h_in)
    data_t[:] = T.ctr256_encrypt(data_t, key, iv_t_in, st_t_in)

    assert data_h == data_t
    assert iv_h_in == iv_t_in
    assert st_h_in == st_t_in

    # Reset mode to auto
    H._set_force_mode(None)

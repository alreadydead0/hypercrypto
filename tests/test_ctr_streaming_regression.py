import os
import random
import pytest
import hypercrypto as H
import tgcrypto as T

def is_dispatch_supported(mode):
    if mode == "portable":
        return True
    if mode == "aesni":
        return H._has_cpu_feature("aes") and H._has_cpu_feature("sse2") and H._has_cpu_feature("ssse3")
    if mode == "vaes256":
        return H._has_cpu_feature("vaes") and H._has_cpu_feature("avx2")
    if mode == "vaes512":
        return (
            H._has_cpu_feature("vaes")
            and H._has_cpu_feature("avx512f")
            and H._has_cpu_feature("avx512vl")
            and H._has_cpu_feature("avx512bw")
        )
    return False

ALL_MODES = ["portable", "aesni", "vaes256", "vaes512"]

@pytest.fixture(params=ALL_MODES)
def force_mode(request):
    mode = request.param
    if not is_dispatch_supported(mode):
        pytest.skip(f"CPU hardware does not support {mode}")
    H._set_force_mode(mode)
    yield mode
    H._set_force_mode(None)

# -------------------------------------------------------------------------------------------------
# 1. Partial-block streaming grid: n1 % 16 in 1..15, n2 in range(1, 300) + [65540]
# -------------------------------------------------------------------------------------------------
GRID_N1 = [4, 20, 68, 100, 132, 260, 1028, 65540]
# Representative sampling of range(1, 300) including boundary edges + 65540
GRID_N2 = [1, 2, 7, 12, 15, 16, 17, 28, 29, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 299, 65540]

@pytest.mark.parametrize("n1", GRID_N1)
@pytest.mark.parametrize("n2", GRID_N2)
def test_partial_block_streaming_grid(force_mode, n1, n2):
    key = os.urandom(32)
    iv_raw = os.urandom(16)
    chunk1 = os.urandom(n1)
    chunk2 = os.urandom(n2)

    # 1. Bytes API Encrypt
    iv_h = bytearray(iv_raw)
    st_h = bytearray(1)
    iv_t = bytearray(iv_raw)
    st_t = bytearray(1)

    c1_h = H.ctr256_encrypt(chunk1, key, iv_h, st_h)
    c1_t = T.ctr256_encrypt(chunk1, key, iv_t, st_t)
    assert c1_h == c1_t
    assert iv_h == iv_t
    assert st_h == st_t

    c2_h = H.ctr256_encrypt(chunk2, key, iv_h, st_h)
    c2_t = T.ctr256_encrypt(chunk2, key, iv_t, st_t)
    assert c2_h == c2_t
    assert iv_h == iv_t
    assert st_h == st_t

    # 2. Bytes API Decrypt
    iv_h_dec = bytearray(iv_raw)
    st_h_dec = bytearray(1)
    p1_h = H.ctr256_decrypt(c1_h, key, iv_h_dec, st_h_dec)
    assert p1_h == chunk1
    p2_h = H.ctr256_decrypt(c2_h, key, iv_h_dec, st_h_dec)
    assert p2_h == chunk2
    assert iv_h_dec == iv_t
    assert st_h_dec == st_t

    # 3. In-Place API Encrypt
    d1_h = bytearray(chunk1)
    d2_h = bytearray(chunk2)
    iv_h_in = bytearray(iv_raw)
    st_h_in = bytearray(1)

    H.ctr256_encrypt_inplace(d1_h, key, iv_h_in, st_h_in)
    assert d1_h == c1_t
    H.ctr256_encrypt_inplace(d2_h, key, iv_h_in, st_h_in)
    assert d2_h == c2_t
    assert iv_h_in == iv_t
    assert st_h_in == st_t

    # 4. In-Place API Decrypt
    H.ctr256_decrypt_inplace(d1_h, key, iv_raw_copy := bytearray(iv_raw), st_raw_copy := bytearray(1))
    assert d1_h == chunk1
    H.ctr256_decrypt_inplace(d2_h, key, iv_raw_copy, st_raw_copy)
    assert d2_h == chunk2

# -------------------------------------------------------------------------------------------------
# 2. Fixed regression cases
# -------------------------------------------------------------------------------------------------
REGRESSION_CASES = [
    [100, 28],
    [4, 20],
    [130, 130],
    [100, 300],
    [5, 1000],
    [65540, 65540],
    [127, 1, 128],
    [3, 3, 3],
]

@pytest.mark.parametrize("chunks", REGRESSION_CASES)
def test_fixed_regression_cases(force_mode, chunks):
    key = os.urandom(32)
    iv_raw = os.urandom(16)
    full_data = b"".join(os.urandom(sz) for sz in chunks)

    # Reference single-call
    ref_iv = bytearray(iv_raw)
    ref_st = bytearray(1)
    ref_ct = T.ctr256_encrypt(full_data, key, ref_iv, ref_st)

    # Multi-chunk streaming via HyperCrypto
    stream_iv = bytearray(iv_raw)
    stream_st = bytearray(1)
    stream_out = []

    pos = 0
    for sz in chunks:
        chunk = full_data[pos : pos + sz]
        ct = H.ctr256_encrypt(chunk, key, stream_iv, stream_st)
        stream_out.append(ct)
        pos += sz

    assert b"".join(stream_out) == ref_ct
    assert stream_iv == ref_iv
    assert stream_st == ref_st

# -------------------------------------------------------------------------------------------------
# 3. Random Split Fuzz (400+ trials, total 2..300000 bytes, random cuts)
# -------------------------------------------------------------------------------------------------
def test_random_split_fuzz(force_mode):
    rng = random.Random(42)
    for _ in range(400):
        total_len = rng.randint(2, 300000)
        data = os.urandom(total_len)
        key = os.urandom(32)
        iv_raw = os.urandom(16)

        num_cuts = rng.randint(1, 6)
        cuts = sorted(rng.sample(range(1, total_len), min(num_cuts, total_len - 1)))
        
        chunks = []
        prev = 0
        for c in cuts:
            chunks.append(data[prev:c])
            prev = c
        chunks.append(data[prev:])

        # Reference TgCrypto
        ref_iv = bytearray(iv_raw)
        ref_st = bytearray(1)
        ref_ct = T.ctr256_encrypt(data, key, ref_iv, ref_st)

        # HyperCrypto stream
        h_iv = bytearray(iv_raw)
        h_st = bytearray(1)
        h_out = []
        for ch in chunks:
            h_out.append(H.ctr256_encrypt(ch, key, h_iv, h_st))

        assert b"".join(h_out) == ref_ct
        assert h_iv == ref_iv
        assert h_st == ref_st

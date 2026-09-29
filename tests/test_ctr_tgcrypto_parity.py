import os
import pytest
import hypercrypto as H
import tgcrypto as T
try:
    import warpcrypto as W
except ImportError:
    W = None

TEST_SIZES = [
    1,
    15,
    16,
    17,
    1000,
    65535,
    65536,
    65537,
    100001,
    3 * 65536 + 123,
]

IV_PATTERNS = [
    ("random", os.urandom(16)),
    ("low_1_0xff", b"\x12" * 15 + b"\xff"),
    ("low_2_0xff", b"\x34" * 14 + b"\xff\xff"),
    ("low_4_0xff", b"\x56" * 12 + b"\xff" * 4),
    ("low_8_0xff", b"\x78" * 8 + b"\xff" * 8),
    ("all_0xff", b"\xff" * 16),
]

KEY = b"K" * 32

@pytest.mark.parametrize("size", TEST_SIZES)
@pytest.mark.parametrize("iv_name, iv_bytes", IV_PATTERNS)
@pytest.mark.parametrize("init_state", [0, 5, 15])
def test_ctr256_encrypt_bytes_parity(size, iv_name, iv_bytes, init_state):
    plaintext = os.urandom(size)

    # Reference: TgCrypto
    iv_t = bytearray(iv_bytes)
    st_t = bytearray([init_state])
    out_t = T.ctr256_encrypt(plaintext, KEY, iv_t, st_t)

    # HyperCrypto
    iv_h = bytearray(iv_bytes)
    st_h = bytearray([init_state])
    out_h = H.ctr256_encrypt(plaintext, KEY, iv_h, st_h)

    assert out_h == out_t, f"Ciphertext mismatch for size={size}, iv={iv_name}, state={init_state}"
    assert iv_h == iv_t, f"Final IV mismatch for size={size}, iv={iv_name}, state={init_state}"
    assert st_h == st_t, f"Final State mismatch for size={size}, iv={iv_name}, state={init_state}"


@pytest.mark.parametrize("size", TEST_SIZES)
@pytest.mark.parametrize("iv_name, iv_bytes", IV_PATTERNS)
@pytest.mark.parametrize("init_state", [0, 7])
def test_ctr256_decrypt_bytes_parity(size, iv_name, iv_bytes, init_state):
    ciphertext = os.urandom(size)

    # Reference: TgCrypto
    iv_t = bytearray(iv_bytes)
    st_t = bytearray([init_state])
    out_t = T.ctr256_decrypt(ciphertext, KEY, iv_t, st_t)

    # HyperCrypto
    iv_h = bytearray(iv_bytes)
    st_h = bytearray([init_state])
    out_h = H.ctr256_decrypt(ciphertext, KEY, iv_h, st_h)

    assert out_h == out_t, f"Decryption output mismatch for size={size}, iv={iv_name}"
    assert iv_h == iv_t, f"Final IV mismatch for size={size}, iv={iv_name}"
    assert st_h == st_t, f"Final State mismatch for size={size}, iv={iv_name}"


@pytest.mark.parametrize("size", TEST_SIZES)
@pytest.mark.parametrize("iv_name, iv_bytes", IV_PATTERNS)
def test_ctr256_inplace_parity(size, iv_name, iv_bytes):
    data = os.urandom(size)

    # Reference: TgCrypto (TgCrypto does not have inplace, so we use its bytes output)
    iv_ref = bytearray(iv_bytes)
    st_ref = bytearray(1)
    ref_out = T.ctr256_encrypt(data, KEY, iv_ref, st_ref)

    # HyperCrypto Inplace Encrypt
    buf_h = bytearray(data)
    iv_h = bytearray(iv_bytes)
    st_h = bytearray(1)
    H.ctr256_encrypt_inplace(buf_h, KEY, iv_h, st_h)

    assert bytes(buf_h) == ref_out, f"Inplace ciphertext mismatch for size={size}"
    assert iv_h == iv_ref, f"Inplace final IV mismatch for size={size}"
    assert st_h == st_ref, f"Inplace final State mismatch for size={size}"

    # HyperCrypto Inplace Decrypt roundtrip
    H.ctr256_decrypt_inplace(buf_h, KEY, bytearray(iv_bytes), bytearray(1))
    assert bytes(buf_h) == data, f"Inplace roundtrip failed for size={size}"


@pytest.mark.parametrize("chunks", [
    [65536, 65536, 65536, 123],
    [100001, 99999],
    [1, 15, 16, 17, 1000, 65535, 65536, 65537],
    [500, 100000, 20000, 50000, 13],
])
def test_streaming_chunk_lists(chunks):
    full_data = os.urandom(sum(chunks))
    iv_seed = os.urandom(16)

    # 1. Single-shot TgCrypto reference
    iv_single = bytearray(iv_seed)
    st_single = bytearray(1)
    expected_single = T.ctr256_encrypt(full_data, KEY, iv_single, st_single)

    # 2. Streaming with TgCrypto
    iv_t = bytearray(iv_seed)
    st_t = bytearray(1)
    chunks_t = []
    idx = 0
    for c_len in chunks:
        part = full_data[idx : idx + c_len]
        idx += c_len
        chunks_t.append(T.ctr256_encrypt(part, KEY, iv_t, st_t))
    tg_stream = b"".join(chunks_t)

    # 3. Streaming with HyperCrypto
    iv_h = bytearray(iv_seed)
    st_h = bytearray(1)
    chunks_h = []
    idx = 0
    for c_len in chunks:
        part = full_data[idx : idx + c_len]
        idx += c_len
        chunks_h.append(H.ctr256_encrypt(part, KEY, iv_h, st_h))
    hyper_stream = b"".join(chunks_h)

    assert hyper_stream == expected_single, "HyperCrypto stream does not match single-shot reference!"
    assert hyper_stream == tg_stream, "HyperCrypto stream does not match TgCrypto stream!"
    assert iv_h == iv_single, "HyperCrypto stream final IV does not match single-shot IV!"
    assert st_h == st_single, "HyperCrypto stream final State does not match single-shot State!"
    assert iv_h == iv_t, "HyperCrypto stream final IV does not match TgCrypto final IV!"
    assert st_h == st_t, "HyperCrypto stream final State does not match TgCrypto final State!"


def test_warpcrypto_sanity_comparison():
    if W is None:
        pytest.skip("warpcrypto not installed")
    # Verify warpcrypto passes same contracts
    data = os.urandom(100001)
    iv_seed = b"\xaa" * 16

    iv_t = bytearray(iv_seed)
    st_t = bytearray(1)
    out_t = T.ctr256_encrypt(data, KEY, iv_t, st_t)

    iv_w = bytearray(iv_seed)
    st_w = bytearray(1)
    out_w = W.ctr256_encrypt(data, KEY, iv_w, st_w)

    iv_h = bytearray(iv_seed)
    st_h = bytearray(1)
    out_h = H.ctr256_encrypt(data, KEY, iv_h, st_h)

    assert out_w == out_t == out_h
    assert iv_w == iv_t == iv_h
    assert st_w == st_t == st_h

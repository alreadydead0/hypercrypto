import os
import hypercrypto

def test_aes_ctr():
    key = os.urandom(32)
    iv = os.urandom(16)
    data = os.urandom(1024)

    # Immutable test
    enc = hypercrypto.ctr256_encrypt(data, key, iv)
    dec = hypercrypto.ctr256_decrypt(enc, key, iv)
    assert dec == data, "CTR roundtrip failed"

    # Inplace test
    buf = bytearray(data)
    hypercrypto.ctr256_encrypt_inplace(buf, key, iv)
    assert bytes(buf) == enc, "CTR in-place encryption mismatch"
    hypercrypto.ctr256_decrypt_inplace(buf, key, iv)
    assert bytes(buf) == data, "CTR in-place decryption mismatch"
    print("[OK] test_aes_ctr passed")

def test_aes_ige():
    key = os.urandom(32)
    iv = os.urandom(32)
    data = os.urandom(512)

    enc = hypercrypto.ige256_encrypt(data, key, iv)
    dec = hypercrypto.ige256_decrypt(enc, key, iv)
    assert dec == data, "IGE roundtrip failed"

    buf = bytearray(data)
    hypercrypto.ige256_encrypt_inplace(buf, key, iv)
    assert bytes(buf) == enc, "IGE in-place encryption mismatch"
    hypercrypto.ige256_decrypt_inplace(buf, key, iv)
    assert bytes(buf) == data, "IGE in-place decryption mismatch"
    print("[OK] test_aes_ige passed")

def test_kdf():
    auth_key = os.urandom(256)
    msg_key = os.urandom(16)
    aes_key, aes_iv = hypercrypto.kdf(auth_key, msg_key, is_outgoing=True)
    assert len(aes_key) == 32
    assert len(aes_iv) == 32
    print("[OK] test_kdf passed")

def test_pack_unpack():
    auth_key = os.urandom(256)
    msg = b"MTProto 2.0 High-Performance Encrypted Message Test"

    packed = hypercrypto.pack_message(auth_key, msg, is_outgoing=True)
    unpacked = hypercrypto.unpack_message(auth_key, packed, is_outgoing=True)
    assert unpacked.startswith(msg), "Unpack message failed to restore original plaintext"
    print("[OK] test_pack_unpack passed")

def test_sha256():
    data = b"Hello HyperCrypto"
    digest = hypercrypto.sha256(data)
    assert len(digest) == 32
    print("[OK] test_sha256 passed")

if __name__ == "__main__":
    test_aes_ctr()
    test_aes_ige()
    test_kdf()
    test_pack_unpack()
    test_sha256()
    print("\nALL HYPERCRYPTO TESTS PASSED SUCCESSFULLY!")

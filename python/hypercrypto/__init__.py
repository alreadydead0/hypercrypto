"""
HyperCrypto: Ultra-fast MTProto 2.0 Cryptographic Engine for Telegram
"""

from .hypercrypto import (
    sha256_digest as sha256,
    ige256_encrypt,
    ige256_decrypt,
    ige256_encrypt_inplace_py as ige256_encrypt_inplace,
    ige256_decrypt_inplace_py as ige256_decrypt_inplace,
    ctr256_encrypt,
    ctr256_decrypt,
    ctr256_encrypt_inplace_py as ctr256_encrypt_inplace,
    ctr256_encrypt_inplace_py as ctr256_decrypt_inplace,
    kdf_py as kdf,
    pack_message,
    unpack_message,
)

__version__ = "0.1.0"
__all__ = [
    "sha256",
    "ige256_encrypt",
    "ige256_decrypt",
    "ige256_encrypt_inplace",
    "ige256_decrypt_inplace",
    "ctr256_encrypt",
    "ctr256_decrypt",
    "ctr256_encrypt_inplace",
    "ctr256_decrypt_inplace",
    "kdf",
    "pack_message",
    "unpack_message",
]

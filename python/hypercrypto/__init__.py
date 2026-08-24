"""
HyperCrypto: Ultra-fast MTProto 2.0 Cryptographic Engine for Telegram
"""

from .hypercrypto import (
    sha256,
    ige256_encrypt,
    ige256_decrypt,
    ige256_encrypt_inplace,
    ige256_decrypt_inplace,
    ctr256_encrypt,
    ctr256_decrypt,
    ctr256_encrypt_inplace,
    ctr256_decrypt_inplace,
    kdf,
    kdf_into,
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
    "kdf_into",
    "pack_message",
    "unpack_message",
]

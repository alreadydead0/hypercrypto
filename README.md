# HyperCrypto

Ultra-fast Next-Generation MTProto 2.0 Cryptographic Engine for Telegram written in Rust with PyO3.

## Features
- **Zero-Copy In-Place Operations**: `ctr256_encrypt_inplace`, `ige256_encrypt_inplace`, `kdf_into`.
- **Vectorized SIMD & Hardware Acceleration**: AES-NI + AVX2 + SHA Extensions.
- **Ultra-Low Latency**: Sub-microsecond KDF and MTProto packet packaging.

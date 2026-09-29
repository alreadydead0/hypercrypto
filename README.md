# HyperCrypto

Ultra high-performance, memory-efficient cryptographic extensions for Telegram MTProto 2.0 written in Rust with PyO3.

## Features

- **MTProto 2.0 Compliant**: Full bit-for-bit compatibility with official Telegram MTProto specifications.
- **Hardware Accelerated**: Optimized for AES-NI, AVX2, SHA-NI on x86_64 and ARMv8 Crypto / NEON on ARM64 with automatic safe software fallback on older processors.
- **Zero-Copy Architecture**: Uses Python's buffer protocol and single-pass allocations (`PyBytes::new_with`) to eliminate intermediate heap buffers.
- **Multi-Platform Support**: Pre-built binary wheels for Windows, Linux (manylinux/musllinux x86_64 and aarch64), and macOS (Intel & Apple Silicon).

## Installation

```bash
pip install hypercrypto
```

No Rust compiler or external C dependencies required for installation.

## API Reference

### 1. AES-256-IGE (RPC & Packet Encryption)
```python
import hypercrypto

# Immutable Bytes API
ciphertext = hypercrypto.ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes
plaintext = hypercrypto.ige256_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes

# Zero-Allocation In-Place API (Accepts bytearray)
hypercrypto.ige256_encrypt_inplace(buffer: bytearray, key: bytes, iv: bytes) -> None
hypercrypto.ige256_decrypt_inplace(buffer: bytearray, key: bytes, iv: bytes) -> None
```

### 2. AES-256-CTR (High-Throughput File Streaming & Downloads)
```python
# Immutable Bytes API (supports stream state tracking)
encrypted = hypercrypto.ctr256_encrypt(data: bytes, key: bytes, iv: bytearray | bytes, state: bytearray = None) -> bytes
decrypted = hypercrypto.ctr256_decrypt(data: bytes, key: bytes, iv: bytearray | bytes, state: bytearray = None) -> bytes

# Zero-Allocation In-Place API
hypercrypto.ctr256_encrypt_inplace(buffer: bytearray, key: bytes, iv: bytearray | bytes, state: bytearray = None) -> None
hypercrypto.ctr256_decrypt_inplace(buffer: bytearray, key: bytes, iv: bytearray | bytes, state: bytearray = None) -> None
```

### 3. MTProto 2.0 KDF (Key Derivation Function)
```python
aes_key, aes_iv = hypercrypto.kdf(auth_key: bytes, msg_key: bytes, is_outgoing: bool) -> tuple[bytes, bytes]

# Zero-Allocation In-Place API
hypercrypto.kdf_into(auth_key, msg_key, is_outgoing, key_out: bytearray, iv_out: bytearray) -> None
```

### 4. End-to-End MTProto Packet Assembly
```python
packed_packet = hypercrypto.pack_message(auth_key: bytes, message: bytes, is_outgoing: bool) -> bytes
unpacked_payload = hypercrypto.unpack_message(auth_key: bytes, encrypted_packet: bytes, is_outgoing: bool) -> bytes
```

## Benchmarks

### AES-256-CTR Throughput Comparison
> Measured on AMD Athlon Silver 3050U (AES, AVX2, SSSE3) | Windows 11 | Python 3.13.5 (min of 7 iterations)

#### 1. Zero-Copy In-Place API (`ctr256_encrypt_inplace`)
| Payload Size | WarpCrypto 2.0.7 | HyperCrypto 0.1.4 | Speedup vs Warp |
| :--- | :--- | :--- | :--- |
| **4 KB** | 1.23 GB/s | **3.67 GB/s** | **2.99x** |
| **16 KB** | 1.42 GB/s | **4.70 GB/s** | **3.30x** |
| **64 KB** | 1.44 GB/s | **5.01 GB/s** | **3.46x** |
| **256 KB** | 1.57 GB/s | **5.15 GB/s** | **3.29x** |
| **512 KB** | 1.33 GB/s | **5.05 GB/s** | **3.79x** |
| **1 MB** | 955 MB/s | **4.98 GB/s** | **5.33x** |
| **4 MB** | 1.05 GB/s | **5.05 GB/s** | **4.82x** |
| **10 MB** | 887 MB/s | **4.80 GB/s** | **5.54x** |
| **16 MB** | 881 MB/s | **4.62 GB/s** | **5.37x** |

#### 2. Immutable Bytes API (`ctr256_encrypt`)
| Payload Size | TgCrypto 1.2.5 | WarpCrypto 2.0.7 | HyperCrypto 0.1.4 | Speedup vs Warp |
| :--- | :--- | :--- | :--- | :--- |
| **4 KB** | 72.9 MB/s | 1.02 GB/s | **3.07 GB/s** | **3.02x** |
| **16 KB** | 81.6 MB/s | 1.26 GB/s | **3.90 GB/s** | **3.09x** |
| **64 KB** | 84.6 MB/s | 1.47 GB/s | **3.97 GB/s** | **2.69x** |
| **256 KB** | 79.9 MB/s | 1.52 GB/s | **4.46 GB/s** | **2.93x** |
| **512 KB** | 77.0 MB/s | 1.17 GB/s | **2.48 GB/s** | **2.12x** |
| **1 MB** | 85.1 MB/s | 994 MB/s | **1.89 GB/s** | **1.94x** |
| **10 MB** | 85.6 MB/s | 825 MB/s | **1.89 GB/s** | **2.35x** |

## License

MIT License. Copyright (c) 2026 alreadydead0.

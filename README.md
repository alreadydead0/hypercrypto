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

No Rust compiler or external C dependencies required for installation (pre-built binary wheels available).

### Building from Source
Building from source requires **Rust 1.89+** (for Vector AES `vaes` intrinsics support) and Python 3.9+:

```bash
git clone https://github.com/alreadydead0/hypercrypto.git
cd hypercrypto
pip install maturin
maturin develop --release
```

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
| Payload Size | WarpCrypto 2.0.7 | HyperCrypto 0.1.5 | Speedup vs Warp |
| :--- | :--- | :--- | :--- |
| **4 KB** | 1.15 GB/s | **3.79 GB/s** | **3.28x** |
| **16 KB** | 1.46 GB/s | **4.74 GB/s** | **3.24x** |
| **64 KB** | 1.41 GB/s | **4.97 GB/s** | **3.52x** |
| **256 KB** | 1.48 GB/s | **4.54 GB/s** | **3.07x** |
| **512 KB** | 885 MB/s | **4.51 GB/s** | **5.22x** |
| **1 MB** | 859 MB/s | **5.09 GB/s** | **6.07x** |
| **4 MB** | 759 MB/s | **4.21 GB/s** | **5.67x** |
| **10 MB** | 556 MB/s | **4.68 GB/s** | **8.62x** |
| **16 MB** | 636 MB/s | **3.18 GB/s** | **5.12x** |

#### 2. Immutable Bytes API (`ctr256_encrypt`)
| Payload Size | TgCrypto 1.2.5 | WarpCrypto 2.0.7 | HyperCrypto 0.1.5 | Speedup vs Warp |
| :--- | :--- | :--- | :--- | :--- |
| **4 KB** | 83.8 MB/s | 1.19 GB/s | **3.14 GB/s** | **2.63x** |
| **16 KB** | 78.6 MB/s | 1.41 GB/s | **3.61 GB/s** | **2.55x** |
| **64 KB** | 83.0 MB/s | 1.36 GB/s | **4.40 GB/s** | **3.23x** |
| **256 KB** | 85.0 MB/s | 1.52 GB/s | **4.54 GB/s** | **3.00x** |
| **512 KB** | 77.9 MB/s | 891 MB/s | **1.88 GB/s** | **2.16x** |
| **1 MB** | 80.0 MB/s | 915 MB/s | **1.92 GB/s** | **2.15x** |
| **10 MB** | 73.9 MB/s | 822 MB/s | **1.75 GB/s** | **2.18x** |

## License

MIT License. Copyright (c) 2026 alreadydead0.

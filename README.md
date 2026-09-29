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

## License

MIT License. Copyright (c) 2026 alreadydead0.

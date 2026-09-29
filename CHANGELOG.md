# Changelog

All notable changes to this project will be documented in this file.

## [0.1.3] - 2026-09-29

### Added
- Hardware-accelerated direct AES-NI SIMD engine with runtime CPU feature detection.
- Single-pass zero-copy streaming for AES-IGE (`ige256_encrypt_slice` / `ige256_decrypt_slice`).
- 8-way parallel pipelined AES-CTR engine achieving >2.5 GB/s throughput.

### Fixed
- Fixed CTR caller `iv` and `state` bytearrays not updating when input length >= 64 KiB across `ctr256_encrypt`, `ctr256_decrypt`, `ctr256_encrypt_inplace`, and `ctr256_decrypt_inplace`.
- Full 128-bit big-endian wrapping counter carry propagation across all chunk sizes and bulk paths.
- Exact partial-block state byte semantics parity with TgCrypto and WarpCrypto.

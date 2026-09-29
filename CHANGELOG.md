# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5] - 2026-09-29

### Fixed
- Fix: CTR streaming corrupted output/iv/state on VAES paths when a chunk ends mid-block and the next chunk continues past it. Affects 0.1.4 on CPUs with VAES. Upgrade recommended.
- Fixed partial-block state byte update ordering across all SIMD and fallback kernels (`vaes512`, `vaes256`, `ni`, `portable`) so downstream tail kernels receive clean zero-state offset.
- Added comprehensive streaming regression test suite (`tests/test_ctr_streaming_regression.py`) covering partial-block streaming grid, fixed regression cases, and 400 random fuzz trials.
- Added `_has_cpu_feature` binding for explicit CPU feature queries.
- Added CI test matrix validating `auto`, `vaes512`, `vaes256`, `aesni`, and `portable` dispatch paths.

## [0.1.4] - 2026-09-29

### Added
- **In-Register Counter Generation**: Eliminated per-block memory load/store roundtrips by keeping the counter in-register (`__m128i`, `__m256i`, `__m512i`) with byte-swapped little-endian representation, advancing via SIMD addition and transforming with `_mm_shuffle_epi8(BSWAP_MASK)`.
- **Unrolled 8-Way AES-NI Kernel**: Locals `b0..b7` with interleaved round encryption to prevent register spilling.
- **VAES-256 (AVX2 + VAES)**: Vector AES 16-way unrolled kernel processing 256 bytes per batch.
- **VAES-512 (AVX-512 + VAES)**: Vector AES 32-way unrolled kernel processing 512 bytes per batch.
- **Dynamic Dispatch & Forced Testing Overrides**: Cached atomic hardware detection supporting `HYPERCRYPTO_FORCE=vaes512|vaes256|aesni|portable` and `_set_force_mode` API.
- **Exhaustive Boundary Parity Tests**: Full verification against TgCrypto for random IVs, low byte 0xFF, low 8 bytes 0xFF, 64-bit carry boundaries, and 128-bit all-0xFF wrap-to-zero across 19 payload sizes.

## [0.1.3] - 2026-09-29

### Added
- Hardware-accelerated direct AES-NI SIMD engine with runtime CPU feature detection.
- Single-pass zero-copy streaming for AES-IGE (`ige256_encrypt_slice` / `ige256_decrypt_slice`).
- 8-way parallel pipelined AES-CTR engine achieving >2.5 GB/s throughput.

### Fixed
- Fixed CTR caller `iv` and `state` bytearrays not updating when input length >= 64 KiB across `ctr256_encrypt`, `ctr256_decrypt`, `ctr256_encrypt_inplace`, and `ctr256_decrypt_inplace`.
- Full 128-bit big-endian wrapping counter carry propagation across all chunk sizes and bulk paths.
- Exact partial-block state byte semantics parity with TgCrypto and WarpCrypto.

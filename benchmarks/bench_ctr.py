import os
import sys
import time
import platform
import statistics

# Ensure utf-8 encoding on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import tgcrypto
import warpcrypto
import hypercrypto

BENCH_SIZES = [
    ("4 KB", 4 * 1024),
    ("16 KB", 16 * 1024),
    ("64 KB", 64 * 1024),
    ("256 KB", 256 * 1024),
    ("512 KB", 512 * 1024),
    ("1 MB", 1 * 1024 * 1024),
    ("4 MB", 4 * 1024 * 1024),
    ("10 MB", 10 * 1024 * 1024),
    ("16 MB", 16 * 1024 * 1024),
]

def get_cpu_brand():
    try:
        import cpuinfo
        info = cpuinfo.get_cpu_info()
        brand = info.get("brand_raw", platform.processor())
        flags = [f for f in info.get("flags", []) if any(x in f for x in ["aes", "vaes", "avx", "sse"])]
        return f"{brand} | Flags: {', '.join(flags)}"
    except Exception:
        return f"{platform.processor()} ({platform.machine()})"

def benchmark_fn(fn, iterations=10, repeats=7):
    # Warmup
    for _ in range(max(2, iterations // 4)):
        fn()
    
    results = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        for _ in range(iterations):
            fn()
        t1 = time.perf_counter_ns()
        results.append((t1 - t0) / iterations)
    return min(results)

def format_mb_s(size_bytes, ns):
    sec = ns / 1e9
    if sec == 0:
        return "N/A"
    mb = size_bytes / (1024 * 1024)
    mb_s = mb / sec
    if mb_s >= 1024:
        return f"{mb_s/1024:6.2f} GB/s"
    return f"{mb_s:6.1f} MB/s"

def run_bench():
    print("=" * 95)
    print("HYPERCRYPTO vs WARPCRYPTO vs TGCRYPTO: AES-256-CTR BENCHMARK")
    print(f"Platform: {platform.system()} {platform.release()} ({platform.machine()}) | Python {sys.version.split()[0]}")
    print(f"CPU: {get_cpu_brand()}")
    force = os.environ.get("HYPERCRYPTO_FORCE", "auto")
    print(f"HYPERCRYPTO_FORCE: {force}")
    print("=" * 95)

    key = b"K" * 32
    iv_const = b"I" * 16

    # 1. BYTES API
    print("\n[1] AES-256-CTR Bytes API (ctr256_encrypt):")
    print(f"{'Size':<10} | {'TgCrypto':<18} | {'WarpCrypto':<18} | {'HyperCrypto':<18} | {'Hyper vs Warp':<15}")
    print("-" * 90)

    for label, size in BENCH_SIZES:
        data = b"\x42" * size
        iters = max(3, min(2000, int(15_000_000 / size)))

        # TgCrypto
        iv_t = bytearray(iv_const)
        st_t = bytearray(1)
        t_ns = benchmark_fn(lambda: tgcrypto.ctr256_encrypt(data, key, iv_t, st_t), iters)

        # WarpCrypto
        iv_w = bytearray(iv_const)
        st_w = bytearray(1)
        w_ns = benchmark_fn(lambda: warpcrypto.ctr256_encrypt(data, key, iv_w, st_w), iters)

        # HyperCrypto
        iv_h = bytearray(iv_const)
        st_h = bytearray(1)
        h_ns = benchmark_fn(lambda: hypercrypto.ctr256_encrypt(data, key, iv_h, st_h), iters)

        ratio = w_ns / h_ns
        ratio_str = f"{ratio:.2f}x faster" if ratio >= 1 else f"{1/ratio:.2f}x slower"
        print(f"{label:<10} | {format_mb_s(size, t_ns):<18} | {format_mb_s(size, w_ns):<18} | {format_mb_s(size, h_ns):<18} | {ratio_str:<15}")

    # 2. INPLACE API
    print("\n[2] AES-256-CTR In-Place API (ctr256_encrypt_inplace):")
    print(f"{'Size':<10} | {'WarpCrypto In-Place':<24} | {'HyperCrypto In-Place':<24} | {'Hyper vs Warp':<15}")
    print("-" * 80)

    for label, size in BENCH_SIZES:
        buf_w = bytearray(b"\x42" * size)
        buf_h = bytearray(b"\x42" * size)
        iters = max(3, min(2000, int(15_000_000 / size)))

        iv_w = bytearray(iv_const)
        st_w = bytearray(1)
        w_ns = benchmark_fn(lambda: warpcrypto.ctr256_encrypt_inplace(buf_w, key, iv_w, st_w), iters)

        iv_h = bytearray(iv_const)
        st_h = bytearray(1)
        h_ns = benchmark_fn(lambda: hypercrypto.ctr256_encrypt_inplace(buf_h, key, iv_h, st_h), iters)

        ratio = w_ns / h_ns
        ratio_str = f"{ratio:.2f}x faster" if ratio >= 1 else f"{1/ratio:.2f}x slower"
        print(f"{label:<10} | {format_mb_s(size, w_ns):<24} | {format_mb_s(size, h_ns):<24} | {ratio_str:<15}")

if __name__ == "__main__":
    run_bench()

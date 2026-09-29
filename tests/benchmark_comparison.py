import time
import os
import sys
import statistics
import hashlib

# Ensure utf-8 encoding on Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import tgcrypto
import warpcrypto
import hypercrypto

# Helper: Pure Python MTProto 2.0 KDF (for comparison since tgcrypto lacks KDF)
def py_kdf(auth_key: bytes, msg_key: bytes, is_outgoing: bool) -> tuple[bytes, bytes]:
    x = 0 if is_outgoing else 8
    sha256_a = hashlib.sha256(msg_key + auth_key[x : x + 36]).digest()
    sha256_b = hashlib.sha256(auth_key[x + 40 : x + 76] + msg_key).digest()
    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv

def time_fn(fn, iterations, warmup=1000):
    for _ in range(warmup):
        fn()
    times = []
    # Batch timings to minimize perf_counter overhead
    batch_size = max(1, min(iterations // 10, 1000))
    total_runs = (iterations // batch_size) * batch_size
    for _ in range(total_runs // batch_size):
        t0 = time.perf_counter_ns()
        for _ in range(batch_size):
            fn()
        t1 = time.perf_counter_ns()
        times.append((t1 - t0) / batch_size)
    return statistics.median(times), statistics.mean(times)

def format_ns(ns):
    if ns < 1000:
        return f"{ns:6.1f} ns"
    elif ns < 1_000_000:
        return f"{ns/1000:6.2f} us"
    else:
        return f"{ns/1_000_000:6.2f} ms"

def format_mb_s(bytes_size, ns):
    seconds = ns / 1_000_000_000.0
    if seconds == 0:
        return "N/A"
    mb = bytes_size / (1024 * 1024)
    mb_s = mb / seconds
    if mb_s >= 1024:
        return f"{mb_s/1024:6.2f} GB/s"
    return f"{mb_s:6.1f} MB/s"

def run_benchmarks():
    print("=" * 80)
    print("ULTIMATE CRYPTO BENCHMARK: WarpCrypto vs TgCrypto vs HyperCrypto")
    print(f"Python: {sys.version.split()[0]} | OS: {sys.platform}")
    print("=" * 80)

    key32 = b"K" * 32
    iv32 = b"I" * 32
    auth_key = b"A" * 256
    msg_key = b"M" * 16

    # -------------------------------------------------------------
    # 1. AES-256-IGE Encryption & Decryption
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("1. AES-256-IGE BENCHMARKS (RPC & Protocol Encryption)")
    print("=" * 80)

    ige_sizes = [
        ("64 B (Ping/Ack)", 64, 25000),
        ("1 KB (Message)", 1024, 15000),
        ("64 KB (Payload)", 65536, 3000),
        ("1 MB (File Block)", 1048576, 300),
    ]

    print("\n--- AES-256-IGE Encryption (Standard) ---")
    print(f"{'Data Size':<20} | {'TgCrypto':<18} | {'WarpCrypto':<18} | {'HyperCrypto':<18} | {'Winner / Speedup'}")
    print("-" * 105)

    for label, size, iters in ige_sizes:
        data = b"X" * size
        t_med, _ = time_fn(lambda: tgcrypto.ige256_encrypt(data, key32, iv32), iters, warmup=iters//10)
        w_med, _ = time_fn(lambda: warpcrypto.ige256_encrypt(data, key32, iv32), iters, warmup=iters//10)
        h_med, _ = time_fn(lambda: hypercrypto.ige256_encrypt(data, key32, iv32), iters, warmup=iters//10)

        best = min(t_med, w_med, h_med)
        winner = "HyperCrypto" if best == h_med else ("WarpCrypto" if best == w_med else "TgCrypto")
        ratio_t = t_med / h_med
        ratio_w = w_med / h_med
        res_text = f"{winner} ({ratio_t:.1f}x vs Tg, {ratio_w:.1f}x vs Warp)" if winner == "HyperCrypto" else f"{winner} (fastest)"

        print(f"{label:<20} | {format_ns(t_med):<9} ({format_mb_s(size, t_med):<7}) | {format_ns(w_med):<9} ({format_mb_s(size, w_med):<7}) | {format_ns(h_med):<9} ({format_mb_s(size, h_med):<7}) | {res_text}")

    print("\n--- AES-256-IGE Decryption (Standard) ---")
    print(f"{'Data Size':<20} | {'TgCrypto':<18} | {'WarpCrypto':<18} | {'HyperCrypto':<18} | {'Winner / Speedup'}")
    print("-" * 105)

    for label, size, iters in ige_sizes:
        data = b"X" * size
        enc = hypercrypto.ige256_encrypt(data, key32, iv32)
        t_med, _ = time_fn(lambda: tgcrypto.ige256_decrypt(enc, key32, iv32), iters, warmup=iters//10)
        w_med, _ = time_fn(lambda: warpcrypto.ige256_decrypt(enc, key32, iv32), iters, warmup=iters//10)
        h_med, _ = time_fn(lambda: hypercrypto.ige256_decrypt(enc, key32, iv32), iters, warmup=iters//10)

        best = min(t_med, w_med, h_med)
        winner = "HyperCrypto" if best == h_med else ("WarpCrypto" if best == w_med else "TgCrypto")
        ratio_t = t_med / h_med
        ratio_w = w_med / h_med
        res_text = f"{winner} ({ratio_t:.1f}x vs Tg, {ratio_w:.1f}x vs Warp)" if winner == "HyperCrypto" else f"{winner} (fastest)"

        print(f"{label:<20} | {format_ns(t_med):<9} ({format_mb_s(size, t_med):<7}) | {format_ns(w_med):<9} ({format_mb_s(size, w_med):<7}) | {format_ns(h_med):<9} ({format_mb_s(size, h_med):<7}) | {res_text}")

    # -------------------------------------------------------------
    # 2. AES-256-IGE In-Place (Zero-Copy)
    # -------------------------------------------------------------
    print("\n--- AES-256-IGE In-Place (Zero-Allocation Buffer API) ---")
    for label, size, iters in ige_sizes:
        buf = bytearray(b"X" * size)
        h_inplace, _ = time_fn(lambda: hypercrypto.ige256_encrypt_inplace(buf, key32, iv32), iters, warmup=iters//10)
        print(f"{label:<20} | HyperCrypto In-Place: {format_ns(h_inplace)} ({format_mb_s(size, h_inplace)}) | TgCrypto: Not Supported | WarpCrypto: Not Supported")

    # -------------------------------------------------------------
    # 3. AES-256-CTR File Downloads & Streaming
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("2. AES-256-CTR BENCHMARKS (File Transfers, Downloads & Media Streaming)")
    print("=" * 80)

    ctr_sizes = [
        ("64 KB (Chunk)", 65536, 4000),
        ("512 KB (TG Part)", 524288, 800),
        ("1 MB (Large Part)", 1048576, 400),
        ("10 MB (Media)", 10485760, 40),
    ]

    print("\n--- AES-256-CTR Encryption (Standard / Throughput) ---")
    print(f"{'Chunk Size':<20} | {'TgCrypto':<18} | {'WarpCrypto':<18} | {'HyperCrypto':<18} | {'Winner / Speedup'}")
    print("-" * 105)

    for label, size, iters in ctr_sizes:
        data = b"Y" * size
        iv_t = bytearray(b"I" * 16)
        state_t = bytearray(1)
        iv_w = bytearray(b"I" * 16)
        state_w = bytearray(1)
        iv_h = bytearray(b"I" * 16)
        state_h = bytearray(1)

        t_med, _ = time_fn(lambda: tgcrypto.ctr256_encrypt(data, key32, iv_t, state_t), iters, warmup=iters//10)
        w_med, _ = time_fn(lambda: warpcrypto.ctr256_encrypt(data, key32, iv_w, state_w), iters, warmup=iters//10)
        h_med, _ = time_fn(lambda: hypercrypto.ctr256_encrypt(data, key32, iv_h, state_h), iters, warmup=iters//10)

        best = min(t_med, w_med, h_med)
        winner = "HyperCrypto" if best == h_med else ("WarpCrypto" if best == w_med else "TgCrypto")
        ratio_t = t_med / h_med
        ratio_w = w_med / h_med
        res_text = f"{winner} ({ratio_t:.1f}x vs Tg, {ratio_w:.1f}x vs Warp)" if winner == "HyperCrypto" else f"{winner} (fastest)"

        print(f"{label:<20} | {format_ns(t_med):<9} ({format_mb_s(size, t_med):<7}) | {format_ns(w_med):<9} ({format_mb_s(size, w_med):<7}) | {format_ns(h_med):<9} ({format_mb_s(size, h_med):<7}) | {res_text}")

    print("\n--- AES-256-CTR Decryption (Standard / Throughput) ---")
    print(f"{'Chunk Size':<20} | {'TgCrypto':<18} | {'WarpCrypto':<18} | {'HyperCrypto':<18} | {'Winner / Speedup'}")
    print("-" * 105)

    for label, size, iters in ctr_sizes:
        data = b"Y" * size
        iv_h = bytearray(b"I" * 16)
        state_h = bytearray(1)
        enc = hypercrypto.ctr256_encrypt(data, key32, iv_h, state_h)

        iv_t = bytearray(b"I" * 16)
        state_t = bytearray(1)
        iv_w = bytearray(b"I" * 16)
        state_w = bytearray(1)
        iv_h2 = bytearray(b"I" * 16)
        state_h2 = bytearray(1)

        t_med, _ = time_fn(lambda: tgcrypto.ctr256_decrypt(enc, key32, iv_t, state_t), iters, warmup=iters//10)
        w_med, _ = time_fn(lambda: warpcrypto.ctr256_decrypt(enc, key32, iv_w, state_w), iters, warmup=iters//10)
        h_med, _ = time_fn(lambda: hypercrypto.ctr256_decrypt(enc, key32, iv_h2, state_h2), iters, warmup=iters//10)

        best = min(t_med, w_med, h_med)
        winner = "HyperCrypto" if best == h_med else ("WarpCrypto" if best == w_med else "TgCrypto")
        ratio_t = t_med / h_med
        ratio_w = w_med / h_med
        res_text = f"{winner} ({ratio_t:.1f}x vs Tg, {ratio_w:.1f}x vs Warp)" if winner == "HyperCrypto" else f"{winner} (fastest)"

        print(f"{label:<20} | {format_ns(t_med):<9} ({format_mb_s(size, t_med):<7}) | {format_ns(w_med):<9} ({format_mb_s(size, w_med):<7}) | {format_ns(h_med):<9} ({format_mb_s(size, h_med):<7}) | {res_text}")

    print("\n--- AES-256-CTR In-Place (Zero-Copy Buffer API) ---")
    print(f"{'Chunk Size':<20} | {'WarpCrypto In-Place':<24} | {'HyperCrypto In-Place':<24} | {'Speedup'}")
    print("-" * 85)

    for label, size, iters in ctr_sizes:
        buf_w = bytearray(b"Y" * size)
        iv_w = bytearray(b"I" * 16)
        state_w = bytearray(1)

        buf_h = bytearray(b"Y" * size)
        iv_h = bytearray(b"I" * 16)
        state_h = bytearray(1)

        w_inplace, _ = time_fn(lambda: warpcrypto.ctr256_encrypt_inplace(buf_w, key32, iv_w, state_w), iters, warmup=iters//10)
        h_inplace, _ = time_fn(lambda: hypercrypto.ctr256_encrypt_inplace(buf_h, key32, iv_h, state_h), iters, warmup=iters//10)

        speedup = w_inplace / h_inplace
        winner = "HyperCrypto" if speedup >= 1 else "WarpCrypto"
        print(f"{label:<20} | {format_ns(w_inplace):<10} ({format_mb_s(size, w_inplace):<9}) | {format_ns(h_inplace):<10} ({format_mb_s(size, h_inplace):<9}) | {winner} is {abs(speedup if speedup >= 1 else 1/speedup):.2f}x faster")

    # -------------------------------------------------------------
    # 4. MTProto 2.0 KDF
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("3. MTPROTO 2.0 KDF BENCHMARK (Key Derivation Function)")
    print("=" * 80)

    iters_kdf = 50000
    py_kdf_time, _ = time_fn(lambda: py_kdf(auth_key, msg_key, True), iters_kdf // 2, warmup=1000)
    w_kdf_time, _ = time_fn(lambda: warpcrypto.kdf(auth_key, msg_key, True), iters_kdf, warmup=1000)
    h_kdf_time, _ = time_fn(lambda: hypercrypto.kdf(auth_key, msg_key, True), iters_kdf, warmup=1000)

    key_out = bytearray(32)
    iv_out = bytearray(32)
    h_kdf_into_time, _ = time_fn(lambda: hypercrypto.kdf_into(auth_key, msg_key, True, key_out, iv_out), iters_kdf, warmup=1000)

    print(f"Pure Python Hashlib KDF  : {format_ns(py_kdf_time)} (Baseline)")
    print(f"TgCrypto KDF             : Not Supported (TgCrypto provides no KDF implementation)")
    print(f"WarpCrypto KDF           : {format_ns(w_kdf_time)} ({py_kdf_time/w_kdf_time:.1f}x vs Python)")
    print(f"HyperCrypto KDF          : {format_ns(h_kdf_time)} ({py_kdf_time/h_kdf_time:.1f}x vs Python, {w_kdf_time/h_kdf_time:.2f}x vs Warp)")
    print(f"HyperCrypto KDF Into     : {format_ns(h_kdf_into_time)} (Zero-Allocation: {w_kdf_time/h_kdf_into_time:.2f}x vs Warp)")

    # -------------------------------------------------------------
    # 5. Pack / Unpack Message Throughput
    # -------------------------------------------------------------
    print("\n" + "=" * 80)
    print("4. END-TO-END PACK / UNPACK MESSAGE BENCHMARK")
    print("=" * 80)

    msg_payload = b"Sample MTProto RPC Query Payload Data for benchmark testing!" * 5
    iters_pack = 20000
    h_pack_time, _ = time_fn(lambda: hypercrypto.pack_message(auth_key, msg_payload, True), iters_pack, warmup=1000)
    packed_h = hypercrypto.pack_message(auth_key, msg_payload, True)
    h_unpack_time, _ = time_fn(lambda: hypercrypto.unpack_message(auth_key, packed_h, True), iters_pack, warmup=1000)

    # WarpCrypto requires (msg_id, seq_no, body, salt, session_id, auth_key, auth_key_id)
    salt = 1234567890123456
    session_id = b"S" * 8
    msg_id = 9876543210987654
    seq_no = 1
    auth_key_id = b"K" * 8

    w_pack_time, _ = time_fn(lambda: warpcrypto.pack_message(msg_id, seq_no, msg_payload, salt, session_id, auth_key, auth_key_id), iters_pack, warmup=1000)
    packed_w = warpcrypto.pack_message(msg_id, seq_no, msg_payload, salt, session_id, auth_key, auth_key_id)
    w_unpack_time, _ = time_fn(lambda: warpcrypto.unpack_message(packed_w, session_id, auth_key, auth_key_id, incoming=True), iters_pack, warmup=1000)

    print(f"{'Operation':<25} | {'WarpCrypto':<15} | {'HyperCrypto':<15} | {'Winner / Speedup'}")
    print("-" * 75)
    winner_pack = "HyperCrypto" if h_pack_time < w_pack_time else "WarpCrypto"
    speedup_pack = w_pack_time / h_pack_time if winner_pack == "HyperCrypto" else h_pack_time / w_pack_time
    print(f"{'Pack Message':<25} | {format_ns(w_pack_time):<15} | {format_ns(h_pack_time):<15} | {winner_pack} is {speedup_pack:.2f}x faster")

    winner_unpack = "HyperCrypto" if h_unpack_time < w_unpack_time else "WarpCrypto"
    speedup_unpack = w_unpack_time / h_unpack_time if winner_unpack == "HyperCrypto" else h_unpack_time / w_unpack_time
    print(f"{'Unpack Message':<25} | {format_ns(w_unpack_time):<15} | {format_ns(h_unpack_time):<15} | {winner_unpack} is {speedup_unpack:.2f}x faster")

    print("\n" + "=" * 80)
    print("🏆 SUMMARY CONCLUSION:")
    print("=" * 80)

if __name__ == "__main__":
    run_benchmarks()

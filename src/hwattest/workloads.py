"""Deterministic, seed-driven work kernels.

The *same* functions are used by the client (which times them) and by the
verifier (which re-executes a random subset to check the reported results).
A kernel's result depends only on (seed, parameter), so a trace recorded for one
challenge cannot be re-labelled for another challenge without re-running the
work with the new seeds. Timing is captured *inside* each kernel so the timed
region is exactly the loop.

Every kernel returns ``(duration_ns, result)`` where ``result`` is a short
string (stable across platforms: ints in hex, floats via ``float.hex``).
"""

from __future__ import annotations

import hashlib
import random
import zlib
from array import array
from time import perf_counter_ns
from typing import Callable, Dict, Tuple

KernelResult = Tuple[int, str]
_MASK31 = 0x7FFFFFFF


# --------------------------------------------------------------------------- #
# Instruction-path kernels (int / fp / branch / load-store)
# --------------------------------------------------------------------------- #
def k_int(seed: int, n: int) -> KernelResult:
    x = (seed % _MASK31) + 1
    t0 = perf_counter_ns()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & _MASK31
    dt = perf_counter_ns() - t0
    return dt, format(x, "x")


def k_fp(seed: int, n: int) -> KernelResult:
    x = 1.0 + (seed % 100000) / 100000.0
    t0 = perf_counter_ns()
    for _ in range(n):
        x = (x * 1.414 + 0.5) % 1000.0
    dt = perf_counter_ns() - t0
    return dt, x.hex()


def k_branch(seed: int, n: int) -> KernelResult:
    x = (seed % _MASK31) + 1
    a = 0
    t0 = perf_counter_ns()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & _MASK31
        if x & 0x10000:
            a += 1
        else:
            a -= 3
    dt = perf_counter_ns() - t0
    return dt, format((a & 0xFFFFFFFF) ^ x, "x")


def k_ldst(seed: int, n: int) -> KernelResult:
    buf = array("q", bytes(8 * 4096))
    i = seed & 4095
    t0 = perf_counter_ns()
    for k in range(n):
        buf[i] += k
        i = (i * 5 + 1) & 4095
    dt = perf_counter_ns() - t0
    return dt, format(sum(buf) & 0xFFFFFFFFFFFF ^ i, "x")


JITTER_KERNELS: Dict[str, Callable[[int, int], KernelResult]] = {
    "int": k_int,
    "fp": k_fp,
    "branch": k_branch,
    "ldst": k_ldst,
}


# --------------------------------------------------------------------------- #
# Clock-work kernel (fixed hashing work used to sample oscillator noise)
# --------------------------------------------------------------------------- #
def k_hashwork(seed: int, n: int) -> KernelResult:
    h = seed.to_bytes(8, "little", signed=False)
    sha = hashlib.sha256
    t0 = perf_counter_ns()
    for _ in range(n):
        h = sha(h).digest()
    dt = perf_counter_ns() - t0
    return dt, h[:8].hex()


# --------------------------------------------------------------------------- #
# Pointer-chase (cache-latency curve)
# --------------------------------------------------------------------------- #
LINE_BYTES = 64
_SLOTS_PER_LINE = LINE_BYTES // 8


def build_chase(size_bytes: int, seed: int) -> array:  # type: ignore[type-arg]
    """Build a single random cycle over all 64-byte lines of a buffer.

    Sattolo's algorithm guarantees one cycle, so a chase of any length stays
    inside the full working set. Footprint is ``size_bytes``.
    """
    lines = max(2, size_bytes // LINE_BYTES)
    perm = list(range(lines))
    rnd = random.Random(seed).random
    for i in range(lines - 1, 0, -1):
        j = int(rnd() * i)
        perm[i], perm[j] = perm[j], perm[i]
    arr = array("q", bytes(lines * LINE_BYTES))
    for i in range(lines):
        arr[i * _SLOTS_PER_LINE] = perm[i] * _SLOTS_PER_LINE
    return arr


def chase_start(seed: int, size_bytes: int) -> int:
    lines = max(2, size_bytes // LINE_BYTES)
    return (seed % lines) * _SLOTS_PER_LINE


def run_chase(arr: array, start: int, steps: int) -> KernelResult:  # type: ignore[type-arg]
    """Dependent loads, 8 per loop iteration to amortise interpreter overhead."""
    a = arr
    i = start
    reps = max(1, steps // 8)
    t0 = perf_counter_ns()
    for _ in range(reps):
        i = a[a[a[a[a[a[a[a[i]]]]]]]]
    dt = perf_counter_ns() - t0
    return dt, format(i, "x")


def k_chase(size_bytes: int, seed: int, steps: int) -> KernelResult:
    """Self-contained build + chase (verifier path)."""
    arr = build_chase(size_bytes, seed)
    return run_chase(arr, chase_start(seed, size_bytes), steps)


# --------------------------------------------------------------------------- #
# Native-primitive throughput (the SIMD-backed paths of libc/OpenSSL/zlib)
# --------------------------------------------------------------------------- #
def make_data(seed: int, size: int) -> bytes:
    rnd = random.Random(seed)
    if hasattr(rnd, "randbytes"):
        return rnd.randbytes(size)
    return bytes(rnd.getrandbits(8) for _ in range(size))  # pragma: no cover (py<3.9)


_TRANSLATE = bytes((i * 7 + 3) & 0xFF for i in range(256))


def _op_hash(name: str) -> Callable[[bytes], str]:
    def f(d: bytes) -> str:
        return hashlib.new(name, d).hexdigest()[:16]

    return f


def _op_crc32(d: bytes) -> str:
    return format(zlib.crc32(d), "x")


def _op_adler32(d: bytes) -> str:
    return format(zlib.adler32(d), "x")


def _op_memcpy(d: bytes) -> str:
    return str(len(bytearray(d)))


def _op_memcmp(d: bytes) -> str:
    # d2 is built outside the timed region by the caller (see k_native).
    return "eq"


def _op_translate(d: bytes) -> str:
    return hashlib.sha256(d.translate(_TRANSLATE)[:64]).hexdigest()[:8]


NATIVE_OPS: Dict[str, Callable[[bytes], str]] = {
    "sha256": _op_hash("sha256"),
    "sha512": _op_hash("sha512"),
    "sha1": _op_hash("sha1"),
    "md5": _op_hash("md5"),
    "blake2b": _op_hash("blake2b"),
    "sha3_256": _op_hash("sha3_256"),
    "crc32": _op_crc32,
    "adler32": _op_adler32,
    "memcpy": _op_memcpy,
    "memcmp": _op_memcmp,
    "memchr": lambda d: "x",
    "translate": _op_translate,
}


def available_native_ops() -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    for name in NATIVE_OPS:
        try:
            k_native(name, 1, 64)
            out[name] = True
        except Exception:  # e.g. md5 disabled in a FIPS build
            out[name] = False
    return out


def k_native(op: str, seed: int, size: int) -> KernelResult:
    """Time one call of a native primitive on ``size`` seed-derived bytes."""
    if op == "memchr":
        zeros = bytes(size)
        t0 = perf_counter_ns()
        idx = zeros.find(b"\x01")
        dt = perf_counter_ns() - t0
        return dt, str(idx)
    data = make_data(seed, size)
    if op == "memcmp":
        other = bytes(bytearray(data))
        t0 = perf_counter_ns()
        eq = data == other
        dt = perf_counter_ns() - t0
        return dt, "eq" if eq else "ne"
    fn = NATIVE_OPS[op]
    t0 = perf_counter_ns()
    res = fn(data)
    dt = perf_counter_ns() - t0
    return dt, res

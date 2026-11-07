"""SIMD timing profile.

Pure Python cannot issue vector instructions directly, so we time the native
primitives the interpreter already links against: OpenSSL hashes (SHA-NI /
ARMv8 crypto / AVX2 paths), zlib checksums, libc memcpy/memchr/memcmp (vector
paths), and scalar contrasts (sha3, translate). The throughput *ratios*
reflect which vector units exist and how fast they are. An emulator that
advertises e.g. ``sha_ni`` but translates it in software flips the
sha256-vs-sha512 ratio.

Also records the SIMD-relevant CPU feature flags (filtered; the full flag list
is only included with --share-raw).
"""

from __future__ import annotations

import platform
import subprocess
import sys
import time
from typing import Any, Dict, List

from ..plan import derive_seed
from ..workloads import NATIVE_OPS, available_native_ops, k_native
from ._ctx import Context

SIMD_FLAGS = {
    # x86
    "sse", "sse2", "ssse3", "sse4_1", "sse4_2", "avx", "avx2", "fma", "avx512f",
    "avx512bw", "avx512vl", "avx512_vnni", "amx_tile", "sha_ni", "aes", "vaes",
    "pclmulqdq", "vpclmulqdq", "gfni",
    # arm
    "neon", "asimd", "asimdhp", "asimddp", "sve", "sve2", "sha1", "sha2", "sha3", "sha512",
    "pmull", "crc32", "atomics", "bf16", "i8mm",
    # power
    "altivec", "vsx", "arch_2_07", "arch_3_00", "vcrypto",
}


def cpu_flags_linux() -> List[str]:
    flags: List[str] = []
    try:
        with open("/proc/cpuinfo", errors="replace") as f:
            for line in f:
                low = line.lower()
                if low.startswith(("flags", "features", "cpu\t", "cpu ")) and ":" in line:
                    flags.extend(line.split(":", 1)[1].strip().lower().split())
                    if low.startswith(("flags", "features")):
                        break
    except OSError:
        pass
    return flags


def cpu_flags_macos() -> List[str]:
    flags: List[str] = []
    try:
        out = subprocess.run(
            ["sysctl", "hw.optional"], capture_output=True, text=True, timeout=5
        ).stdout
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                if v.strip() == "1":
                    flags.append(k.strip().rsplit(".", 1)[-1].lower())
    except (OSError, subprocess.SubprocessError):
        pass
    return flags


def all_cpu_flags() -> List[str]:
    if sys.platform.startswith("linux"):
        return cpu_flags_linux()
    if sys.platform == "darwin":
        return cpu_flags_macos()
    return []


def simd_relevant(flags: List[str]) -> List[str]:
    out = set()
    for f in flags:
        prefixed = f.startswith(("feat_sha", "feat_aes", "feat_pmull", "feat_sve", "avx512"))
        if f in SIMD_FLAGS or prefixed or f in ("arm64", "armv8"):
            out.add(f)
    m = platform.machine().lower()
    if m.startswith(("ppc", "power")) and "altivec" not in out and "vsx" in flags:
        out.add("altivec")
    return sorted(out)


def run(params: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    deadline = ctx.deadline()
    avail = available_native_ops()
    samples: List[List[Any]] = []
    truncated = False
    for idx, (op, size) in enumerate(params.get("schedule", [])):
        if time.perf_counter_ns() > deadline:
            truncated = True
            break
        if op not in NATIVE_OPS or not avail.get(op, False):
            continue
        seed = derive_seed(ctx.master_seed, "simd", idx)
        t0 = ctx.rel()
        dur, res = k_native(op, seed, int(size))
        samples.append([idx, op, int(size), t0, dur, res])
    flags = all_cpu_flags()
    return {
        "samples": samples,
        "truncated": truncated,
        "ops_available": sorted(k for k, v in avail.items() if v),
        "simd_flags": simd_relevant(flags),
        "_all_flags": flags,  # stripped from the shared payload unless --share-raw
    }

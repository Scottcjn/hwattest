"""Measurement plans: the randomized parameters a client must execute exactly.

A plan is plain JSON. The server generates it inside a challenge (see
``challenge.py``); for local-only use the client can generate its own
("self-issued") plan, which a relying party should treat as unverified.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any, Dict, List

from .workloads import JITTER_KERNELS, NATIVE_OPS

PLAN_VERSION = 1

PROFILES: Dict[str, Dict[str, Any]] = {
    # ~5 s on a 2024 laptop, minutes on vintage machines; every module has a hard 60 s cap.
    "standard": {
        "cache_log2": (12.0, 26.0, 1.0),  # 4 KiB .. 64 MiB, one octave apart
        "cache_reps": 9,
        "cache_steps": (32000, 96000),
        "jitter_per_kind": 200,
        "jitter_n": (4000, 16000),
        "clock_reads": 20000,
        "clock_samples": 400,
        "clock_n": (200, 800),
        "simd_per_op": 16,
        "simd_size_log2": (12.0, 20.0),
        "module_budget_s": 60.0,
    },
    "quick": {
        "cache_log2": (12.0, 25.0, 1.5),
        "cache_reps": 3,
        "cache_steps": (8000, 16000),
        "jitter_per_kind": 40,
        "jitter_n": (2000, 8000),
        "clock_reads": 5000,
        "clock_samples": 60,
        "clock_n": (100, 400),
        "simd_per_op": 5,
        "simd_size_log2": (12.0, 18.0),
        "module_budget_s": 20.0,
    },
    # For unit tests only: finishes in well under a second.
    "tiny": {
        "cache_log2": (12.0, 16.0, 2.0),
        "cache_reps": 2,
        "cache_steps": (800, 1600),
        "jitter_per_kind": 12,
        "jitter_n": (200, 800),
        "clock_reads": 500,
        "clock_samples": 12,
        "clock_n": (10, 40),
        "simd_per_op": 4,
        "simd_size_log2": (10.0, 13.0),
        "module_budget_s": 10.0,
    },
}


def derive_seed(master: int, module: str, idx: int) -> int:
    """Per-sample seed: a pure function of the plan seed, module and index."""
    h = hashlib.sha256(f"{master}:{module}:{idx}".encode()).digest()
    return int.from_bytes(h[:8], "little") & ((1 << 63) - 1)


def make_plan(rng: random.Random, profile: str = "standard", tpm: bool = False) -> Dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    p = PROFILES[profile]
    seed = rng.getrandbits(63)

    # Cache: jittered log grid, shuffled execution order, random step counts.
    lo, hi, step = p["cache_log2"]
    sizes: List[int] = []
    x = lo
    while x <= hi + 1e-9:
        jit = rng.uniform(-0.35, 0.35) * step
        s = int(2 ** max(lo, min(hi, x + jit)))
        s = max(4096, (s // 4096) * 4096)
        if s not in sizes:
            sizes.append(s)
        x += step
    rng.shuffle(sizes)
    smin, smax = p["cache_steps"]
    cache_items = [
        {"size": s, "steps": [rng.randint(smin, smax) for _ in range(p["cache_reps"])]}
        for s in sizes
    ]

    # Jitter: interleaved kinds, random loop counts per sample.
    jlo, jhi = p["jitter_n"]
    sched = [
        [kind, rng.randint(jlo, jhi)]
        for kind in sorted(JITTER_KERNELS)
        for _ in range(p["jitter_per_kind"])
    ]
    rng.shuffle(sched)

    # Clock: random hashing work per sample.
    clo, chi = p["clock_n"]
    clock_work = [rng.randint(clo, chi) for _ in range(p["clock_samples"])]

    # Native primitives: random sizes, shuffled.
    slo, shi = p["simd_size_log2"]
    simd_sched = [
        [op, int(2 ** rng.uniform(slo, shi))]
        for op in sorted(NATIVE_OPS)
        for _ in range(p["simd_per_op"])
    ]
    rng.shuffle(simd_sched)

    order = ["clock", "cache", "jitter", "simd"]
    rng.shuffle(order)

    return {
        "v": PLAN_VERSION,
        "profile": profile,
        "seed": seed,
        "order": order,
        "module_budget_s": p["module_budget_s"],
        "clock": {"reads": p["clock_reads"], "work": clock_work},
        "cache": {"items": cache_items},
        "jitter": {"schedule": sched},
        "simd": {"schedule": simd_sched},
        "tpm": {"quote": bool(tpm)},
    }


def expected_counts(plan: Dict[str, Any]) -> Dict[str, int]:
    """Number of samples a complete run of ``plan`` produces, per module."""
    return {
        "clock": len(plan["clock"]["work"]),
        "cache": sum(len(it["steps"]) for it in plan["cache"]["items"]),
        "jitter": len(plan["jitter"]["schedule"]),
        "simd": len(plan["simd"]["schedule"]),
    }

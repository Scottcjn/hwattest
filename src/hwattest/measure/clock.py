"""Clock / oscillator measurement.

Three things, all returned as distributions or figures, never as pass/fail:

1. **Clock-read cost**: back-to-back ``perf_counter_ns`` deltas. The
   distribution (min, median, tail, granularity) differs between a native TSC,
   a paravirtual clock (kvm-clock/hyperv), HPET, and emulated timers.
2. **Work-sample timing**: fixed hashing work with plan-chosen sizes; the
   residual noise is oscillator + scheduler jitter.
3. **Frequency correction**: NTP-disciplined MONOTONIC vs MONOTONIC_RAW over
   the session (``Context.slew_ppm``) and, on Linux, ``adjtimex`` read-only.

Ported and reworked from Elyan Labs' earlier clock-drift check (Apache-2.0).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
import time
from typing import Any, Dict, List, Optional

from .. import _stats
from ..plan import derive_seed
from ..workloads import k_hashwork
from ._ctx import Context


def read_cost(n: int) -> Dict[str, Any]:
    pc = time.perf_counter_ns
    deltas: List[int] = []
    for _ in range(n):
        a = pc()
        b = pc()
        deltas.append(b - a)
    return describe_read_deltas(deltas)


def describe_read_deltas(deltas: List[int]) -> Dict[str, Any]:
    """Summarise clock-read deltas (pure function; unit-testable)."""
    if not deltas:
        return {"n": 0}
    s = _stats.summarize([float(d) for d in deltas])
    zero = sum(1 for d in deltas if d == 0)
    return {
        "n": len(deltas),
        "min_ns": s["min"],
        "p50_ns": s["p50"],
        "p90_ns": s["p90"],
        "p99_ns": s["p99"],
        "zero_frac": zero / len(deltas),
        "granularity_ns": _stats.gcd_list(deltas),
        "distinct": min(len(set(deltas)), 1000),
    }


def clocksource() -> Dict[str, Optional[str]]:
    base = "/sys/devices/system/clocksource/clocksource0/"
    out: Dict[str, Optional[str]] = {"current": None, "available": None}
    for key, fn in (("current", "current_clocksource"), ("available", "available_clocksource")):
        try:
            with open(base + fn) as f:
                out[key] = f.read().strip()
        except OSError:
            pass
    return out


class _Timex(ctypes.Structure):
    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long),
        ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long),
        ("esterror", ctypes.c_long),
        ("status", ctypes.c_int),
        ("constant", ctypes.c_long),
        ("precision", ctypes.c_long),
        ("tolerance", ctypes.c_long),
        ("time_sec", ctypes.c_long),
        ("time_usec", ctypes.c_long),
        ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long),
        ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long),
        ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long),
        ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int),
        ("_pad", ctypes.c_int * 16),
    ]


def adjtimex_readonly() -> Optional[Dict[str, Any]]:
    """Kernel NTP state via adjtimex(modes=0). Unprivileged and read-only."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        tx = _Timex()
        tx.modes = 0
        state = libc.adjtimex(ctypes.byref(tx))
        if state < 0:
            return None
        return {
            # freq is in 2^-16 ppm; rounded to 0.25 ppm for privacy.
            "freq_ppm": round(tx.freq / 65536.0 * 4) / 4,
            "unsync": bool(tx.status & 0x40),
            "state": int(state),
        }
    except (OSError, AttributeError, ValueError):
        return None


def run(params: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    deadline = ctx.deadline()
    out: Dict[str, Any] = {"read_cost": read_cost(int(params.get("reads", 0)))}
    samples: List[List[Any]] = []
    truncated = False
    for idx, n in enumerate(params.get("work", [])):
        if time.perf_counter_ns() > deadline:
            truncated = True
            break
        seed = derive_seed(ctx.master_seed, "clock", idx)
        t0 = ctx.rel()
        dur, res = k_hashwork(seed, int(n))
        samples.append([idx, int(n), t0, dur, res])
        if idx % 20 == 0:
            ctx.checkpoint()
    out["samples"] = samples
    out["truncated"] = truncated
    out["clocksource"] = clocksource()
    out["adjtimex"] = adjtimex_readonly()
    out["has_monotonic_raw"] = hasattr(time, "CLOCK_MONOTONIC_RAW")
    out["pid_cpu_count"] = (
        len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    )
    return out

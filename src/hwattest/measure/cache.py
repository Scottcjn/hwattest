"""Cache-latency curve via random pointer chasing.

For each plan-chosen buffer size we build one random cycle over its 64-byte
lines and time chains of dependent loads. ns/step versus working-set size
shows the L1/L2/L3/DRAM (and TLB) knees. Interpreter overhead adds a constant
per step, so the *shape* (excess over the smallest size) is the signal.

Reworked from Elyan Labs' earlier cache-timing sweep (Apache-2.0), which timed
sequential bytearray reads; dependent random loads defeat the prefetcher.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from ..plan import derive_seed
from ..workloads import LINE_BYTES, build_chase, chase_start, run_chase
from ._ctx import Context


def run(params: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    deadline = ctx.deadline()
    samples: List[List[Any]] = []
    skipped: List[int] = []
    truncated = False
    for idx, item in enumerate(params.get("items", [])):
        if time.perf_counter_ns() > deadline:
            truncated = True
            break
        size = int(item["size"])
        seed = derive_seed(ctx.master_seed, "cache", idx)
        try:
            arr = build_chase(size, seed)
        except MemoryError:
            skipped.append(idx)
            continue
        lines = max(2, size // LINE_BYTES)
        # Untimed warm-up pass: fault in pages, settle the working set.
        run_chase(arr, chase_start(seed, size), min(lines, 262144))
        for rep, steps in enumerate(item["steps"]):
            if time.perf_counter_ns() > deadline:
                truncated = True
                break
            rseed = derive_seed(seed, "rep", rep)
            t0 = ctx.rel()
            dur, res = run_chase(arr, chase_start(rseed, size), int(steps))
            samples.append([idx, rep, size, int(steps), t0, dur, res])
        del arr
        ctx.checkpoint()
        if truncated:
            break
    return {"samples": samples, "skipped": skipped, "truncated": truncated}

"""Instruction-path jitter: int / fp / branch / load-store loops.

The plan interleaves kinds and randomizes loop counts per sample, so the
server can fit duration ~ count per kind (per-op cost + overhead) and look at
the residual distribution (jitter, preemption tail, autocorrelation).

Reworked from Elyan Labs' earlier instruction-jitter check (Apache-2.0).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from ..plan import derive_seed
from ..workloads import JITTER_KERNELS
from ._ctx import Context


def run(params: Dict[str, Any], ctx: Context) -> Dict[str, Any]:
    deadline = ctx.deadline()
    samples: List[List[Any]] = []
    truncated = False
    for idx, (kind, n) in enumerate(params.get("schedule", [])):
        if time.perf_counter_ns() > deadline:
            truncated = True
            break
        fn = JITTER_KERNELS.get(kind)
        if fn is None:
            continue
        seed = derive_seed(ctx.master_seed, "jitter", idx)
        t0 = ctx.rel()
        dur, res = fn(seed, int(n))
        samples.append([idx, kind, int(n), t0, dur, res])
        if idx % 50 == 0:
            ctx.checkpoint()
    return {"samples": samples, "truncated": truncated}

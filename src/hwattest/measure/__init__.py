"""Client-side measurement. Runs a plan and returns the local (full) record.

The full record contains ``_raw`` / ``_all_flags`` keys holding identifying
strings; ``hwattest.privacy.build_payload`` removes them unless the user opts
in with ``--share-raw``.
"""

from __future__ import annotations

import platform
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from .. import __version__
from . import cache, clock, jitter, simd, tpm, vmind
from ._ctx import Context

MODULES: Dict[str, Callable[[Dict[str, Any], Context], Dict[str, Any]]] = {
    "clock": clock.run,
    "cache": cache.run,
    "jitter": jitter.run,
    "simd": simd.run,
}


def run_plan(
    plan: Dict[str, Any],
    nonce: str = "",
    only: Optional[List[str]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    ctx = Context(int(plan["seed"]), float(plan.get("module_budget_s", 60.0)))
    wall_start = time.time()
    steal0 = vmind.read_steal_ticks()

    vm = vmind.run()
    results: Dict[str, Any] = {"vm": vm}
    durations: Dict[str, int] = {}
    for name in plan.get("order", list(MODULES)):
        if only is not None and name not in only:
            continue
        fn = MODULES.get(name)
        if fn is None:
            continue
        if progress:
            progress(name)
        t = ctx.rel()
        try:
            results[name] = fn(plan.get(name, {}), ctx)
        except Exception as e:  # a module must never crash the whole run
            results[name] = {"samples": [], "error": f"{type(e).__name__}: {e}"[:200]}
        durations[name] = ctx.rel() - t
        ctx.checkpoint()

    if only is None or "tpm" in only:
        results["tpm"] = tpm.run(plan.get("tpm"), nonce)

    steal1 = vmind.read_steal_ticks()
    ctx.checkpoint()
    session = {
        "elapsed_ns": ctx.rel(),
        "module_ns": durations,
        "checkpoints": ctx.checkpoints,
        "slew_ppm": ctx.slew_ppm(),
        "steal_ticks_delta": (
            steal1 - steal0 if steal0 is not None and steal1 is not None else None
        ),
        "wall_start": round(wall_start, 3),
    }
    return {
        "client": {
            "hwattest": __version__,
            "python": platform.python_version(),
            "impl": platform.python_implementation(),
            "platform": sys.platform,
            "arch": platform.machine().lower(),
        },
        "session": session,
        "results": results,
    }

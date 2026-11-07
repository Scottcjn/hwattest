"""Feature extraction from raw measurement samples (server side).

The server never trusts client-side summaries: every statistic used for
scoring and clustering is recomputed here from the per-sample records.
All functions are pure and tolerate missing / partial data.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .. import _stats

GRID_LOG2 = list(range(12, 27))  # 4 KiB .. 64 MiB


def fit_linear(ns: Sequence[float], durs: Sequence[float]) -> Dict[str, float]:
    """Robust fit dur = a + b*n and residual statistics."""
    if len(ns) < 3:
        return {}
    a, b = _stats.theil_sen(ns, durs)
    resid = [durs[i] - (a + b * ns[i]) for i in range(len(ns))]
    pred_med = _stats.median([a + b * x for x in ns]) or 1.0
    m = _stats.mad(resid)
    tail = sum(1 for r in resid if r > 5 * 1.4826 * m + 1e-9) / len(resid) if m > 0 else 0.0
    return {
        "per_op_ns": b,
        "overhead_ns": a,
        "spearman": _stats.spearman(ns, durs),
        "resid_rcv": 1.4826 * m / pred_med,
        "tail_frac": tail,
        "lag1": _stats.lag1_autocorr(resid),
        "n": float(len(ns)),
    }


def clock_features(clock: Dict[str, Any], session: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    rc = clock.get("read_cost") or {}
    for k in ("min_ns", "p50_ns", "p99_ns", "granularity_ns", "zero_frac", "distinct"):
        if k in rc:
            out[f"read_{k}"] = rc[k]
    samples = clock.get("samples") or []
    if samples:
        ns = [float(s[1]) for s in samples]
        durs = [float(s[3]) for s in samples]
        out["work"] = fit_linear(ns, durs)
    out["slew_ppm"] = session.get("slew_ppm")
    adj = clock.get("adjtimex") or {}
    out["adjtimex_freq_ppm"] = adj.get("freq_ppm")
    out["ntp_unsync"] = adj.get("unsync")
    cs = clock.get("clocksource") or {}
    out["clocksource"] = cs.get("current")
    return out


def cache_curve(samples: List[List[Any]]) -> List[Tuple[int, float, float]]:
    """[(size, median ns/step, robust cv across reps)] sorted by size."""
    by: Dict[int, List[float]] = {}
    for s in samples:
        size, steps, dur = int(s[2]), int(s[3]), float(s[5])
        if steps > 0:
            by.setdefault(size, []).append(dur / steps)
    return [(k, _stats.median(v), _stats.robust_cv(v)) for k, v in sorted(by.items())]


def cache_features(cache: Dict[str, Any]) -> Dict[str, Any]:
    curve = cache_curve(cache.get("samples") or [])
    out: Dict[str, Any] = {"points": len(curve)}
    if len(curve) < 3:
        return out
    xs = [math.log2(c[0]) for c in curve]
    ys = [c[1] for c in curve]
    base = min(ys[:2])
    grid: Dict[str, Optional[float]] = {}
    for g in GRID_LOG2:
        if xs[0] - 0.5 <= g <= xs[-1] + 0.5:
            v = _stats.interp(float(g), xs, ys)
            grid[str(g)] = None if v is None else v - base
        else:
            grid[str(g)] = None
    final_excess = ys[-1] - base
    knee: Optional[float] = None
    thresh = max(3.0, 0.25 * final_excess)
    for x, y in zip(xs, ys):
        if y - base > thresh:
            knee = x
            break
    out.update(
        {
            "base_ns": base,
            "max_log2": xs[-1],
            "final_excess_ns": final_excess,
            "excess_ratio": ys[-1] / base if base > 0 else 0.0,
            "knee_log2": knee,
            "monotonic_spearman": _stats.spearman(xs, ys),
            "rep_rcv_median": _stats.median([c[2] for c in curve]),
            "excess_grid": grid,
        }
    )
    return out


def jitter_features(jitter: Dict[str, Any]) -> Dict[str, Any]:
    by: Dict[str, Tuple[List[float], List[float]]] = {}
    for s in jitter.get("samples") or []:
        kind, n, dur = str(s[1]), float(s[2]), float(s[4])
        ns, ds = by.setdefault(kind, ([], []))
        ns.append(n)
        ds.append(dur)
    out: Dict[str, Any] = {k: fit_linear(v[0], v[1]) for k, v in sorted(by.items())}
    base = (out.get("int") or {}).get("per_op_ns")
    if base:
        for k in ("fp", "branch", "ldst"):
            po = (out.get(k) or {}).get("per_op_ns")
            if po:
                out[f"ratio_{k}_int"] = po / base
    return out


def simd_features(simd: Dict[str, Any]) -> Dict[str, Any]:
    by: Dict[str, Tuple[List[float], List[float]]] = {}
    for s in simd.get("samples") or []:
        op, size, dur = str(s[1]), float(s[2]), float(s[4])
        xs, ds = by.setdefault(op, ([], []))
        xs.append(size)
        ds.append(dur)
    ops: Dict[str, Dict[str, float]] = {}
    for op, (xs, ds) in sorted(by.items()):
        f = fit_linear(xs, ds)
        if f and f["per_op_ns"] > 0:
            ops[op] = {
                "gbps": 1.0 / f["per_op_ns"],  # bytes/ns == GB/s
                "overhead_ns": f["overhead_ns"],
                "spearman": f["spearman"],
            }
    out: Dict[str, Any] = {"ops": ops, "flags": list(simd.get("simd_flags") or [])}
    logs = {op: math.log2(v["gbps"]) for op, v in ops.items() if v["gbps"] > 0}
    if len(logs) >= 3:
        # Centre on the median op: robust to noise in any single reference op.
        mid = _stats.median(list(logs.values()))
        out["profile"] = {op: v - mid for op, v in logs.items()}
    if "memcpy" in logs and "sha256" in logs:
        out["log2_memcpy_over_sha256"] = logs["memcpy"] - logs["sha256"]
    s256 = (ops.get("sha256") or {}).get("gbps")
    s512 = (ops.get("sha512") or {}).get("gbps")
    if s256 and s512:
        out["sha256_over_sha512"] = s256 / s512
    return out


def extract(record: Dict[str, Any]) -> Dict[str, Any]:
    """All features from a (payload or local) record."""
    res = record.get("results") or {}
    session = record.get("session") or {}
    feats: Dict[str, Any] = {
        "clock": clock_features(res.get("clock") or {}, session),
        "cache": cache_features(res.get("cache") or {}),
        "jitter": jitter_features(res.get("jitter") or {}),
        "simd": simd_features(res.get("simd") or {}),
        "vm": dict((res.get("vm") or {}).get("features") or {}),
        "session": {
            "elapsed_ns": session.get("elapsed_ns"),
            "steal_ticks_delta": session.get("steal_ticks_delta"),
        },
    }
    # Cross-module physical ratios.
    int_op = ((feats["jitter"].get("int") or {}).get("per_op_ns")) or None
    fe = feats["cache"].get("final_excess_ns")
    if int_op and fe is not None and feats["cache"].get("max_log2", 0) >= 24:
        # DRAM latency is physical; interpreter speed is CPU speed. An emulator
        # slows the interpreter ~5-20x but not the host's DRAM, so this ratio
        # collapses under binary translation.
        feats["cross"] = {"dram_excess_over_int_op": fe / int_op}
    else:
        feats["cross"] = {}
    return feats

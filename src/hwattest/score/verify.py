"""Challenge-response verification: binding, parameters, timing plausibility.

Hard failures (``rejections``) mean the submission does not correspond to a
fresh execution of *this* challenge's plan. Soft findings (``warnings``)
lower the integrity score but do not reject on their own.

What this can and cannot establish is documented in README ("Honest limits"):
it forces an attacker to execute (or faithfully model) the randomized plan
for every submission; it cannot prove the timings were not synthesized by a
patched client that models our checks.
"""

from __future__ import annotations

import hashlib
import random
import secrets
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import _stats
from ..challenge import FORMAT
from ..plan import derive_seed, expected_counts
from ..workloads import (
    JITTER_KERNELS,
    build_chase,
    chase_start,
    k_hashwork,
    k_native,
    run_chase,
)

# Python cannot run a loop iteration in under ~1 ns on any CPU we know of;
# anything faster than this per unit of work is fabricated.
MIN_NS_PER_UNIT = {"clock": 20.0, "jitter": 1.0, "cache": 1.0, "simd": 0.0005}
CLOCK_SLACK_S = 2.0
MIN_COMPLETE_FRACTION = 0.5
CONSISTENCY_HARD = 0.2   # Spearman(param, duration) below this is not a real run
CONSISTENCY_SOFT = 0.6
TOO_PERFECT = 0.9995
COMMON_MODE_MIN_PAIRS = 30


def _t0_idx(module: str) -> int:
    return {"clock": 2, "cache": 4, "jitter": 3, "simd": 3}[module]


def _dur_idx(module: str) -> int:
    return {"clock": 3, "cache": 5, "jitter": 4, "simd": 4}[module]


def trace_hash(results: Dict[str, Any]) -> str:
    h = hashlib.sha256()
    for mod in ("clock", "cache", "jitter", "simd"):
        for s in (results.get(mod) or {}).get("samples") or []:
            h.update(str(s[_dur_idx(mod)]).encode() + b",")
        h.update(b"|")
    return h.hexdigest()


def _expected_param(plan: Dict[str, Any], module: str, sample: List[Any]) -> Tuple[bool, str]:
    """Does this sample carry exactly the plan's parameters at its index?"""
    try:
        if module == "clock":
            idx = int(sample[0])
            return int(sample[1]) == int(plan["clock"]["work"][idx]), "clock"
        if module == "jitter":
            idx = int(sample[0])
            kind, n = plan["jitter"]["schedule"][idx]
            return (sample[1] == kind and int(sample[2]) == int(n)), "jitter"
        if module == "simd":
            idx = int(sample[0])
            op, size = plan["simd"]["schedule"][idx]
            return (sample[1] == op and int(sample[2]) == int(size)), "simd"
        if module == "cache":
            idx, rep = int(sample[0]), int(sample[1])
            item = plan["cache"]["items"][idx]
            return (
                int(sample[2]) == int(item["size"]) and int(sample[3]) == int(item["steps"][rep])
            ), "cache"
    except (IndexError, KeyError, TypeError, ValueError):
        return False, module
    return False, module


def _sample_key(module: str, s: List[Any]) -> Tuple[int, int]:
    return (int(s[0]), int(s[1])) if module == "cache" else (int(s[0]), 0)


def _plan_keys(plan: Dict[str, Any], module: str) -> List[Tuple[int, int]]:
    if module == "cache":
        return [
            (i, r) for i, it in enumerate(plan["cache"]["items"]) for r in range(len(it["steps"]))
        ]
    n = expected_counts(plan)[module]
    return [(i, 0) for i in range(n)]


def _work_units(module: str, s: List[Any]) -> float:
    return float(
        {"clock": s[1], "jitter": s[2], "cache": s[3], "simd": s[2]}[module]
    )


def _recompute(plan: Dict[str, Any], module: str, s: List[Any]) -> Optional[str]:
    seed0 = int(plan["seed"])
    if module == "clock":
        return k_hashwork(derive_seed(seed0, "clock", int(s[0])), int(s[1]))[1]
    if module == "jitter":
        fn = JITTER_KERNELS[str(s[1])]
        return fn(derive_seed(seed0, "jitter", int(s[0])), int(s[2]))[1]
    if module == "simd":
        return k_native(str(s[1]), derive_seed(seed0, "simd", int(s[0])), int(s[2]))[1]
    if module == "cache":
        idx, rep, size, steps = int(s[0]), int(s[1]), int(s[2]), int(s[3])
        seed = derive_seed(seed0, "cache", idx)
        arr = build_chase(size, seed)
        rseed = derive_seed(seed, "rep", rep)
        return run_chase(arr, chase_start(rseed, size), steps)[1]
    return None


def consistency(module: str, samples: List[List[Any]]) -> Optional[float]:
    """Spearman correlation between requested work and reported duration.

    Computed per sub-kind and averaged (weighted by count). Real executions
    are ~0.9+; durations recycled from another plan are ~0.
    """
    groups: Dict[str, Tuple[List[float], List[float]]] = {}
    for s in samples:
        if module == "jitter" or module == "simd":
            key = str(s[1])
        elif module == "cache":
            key = str(s[2])  # within a size, steps vary
        else:
            key = "all"
        xs, ys = groups.setdefault(key, ([], []))
        xs.append(_work_units(module, s))
        ys.append(float(s[_dur_idx(module)]))
    tot = 0.0
    wsum = 0
    for xs, ys in groups.values():
        if len(xs) >= 3 and len(set(xs)) > 1:
            tot += _stats.spearman(xs, ys) * len(xs)
            wsum += len(xs)
    return tot / wsum if wsum else None


def common_mode(samples: List[List[Any]]) -> Optional[float]:
    """Correlation of normalized residuals of time-adjacent jitter samples of
    *different* kinds. Shared physical state (clock frequency, thermal, load)
    makes this positive on real executions; per-kind re-mapped traces lose it.
    """
    by: Dict[str, Tuple[List[float], List[float]]] = {}
    for s in samples:
        xs, ys = by.setdefault(str(s[1]), ([], []))
        xs.append(float(s[2]))
        ys.append(float(s[4]))
    fits = {k: _stats.theil_sen(v[0], v[1]) for k, v in by.items() if len(v[0]) >= 5}
    order = sorted(samples, key=lambda s: float(s[3]))
    a: List[float] = []
    b: List[float] = []
    prev: Optional[Tuple[str, float]] = None
    for s in order:
        k = str(s[1])
        if k not in fits:
            continue
        ia, sl = fits[k]
        pred = ia + sl * float(s[2])
        if pred <= 0:
            continue
        r = float(s[4]) / pred - 1.0
        if prev is not None and prev[0] != k:
            a.append(prev[1])
            b.append(r)
        prev = (k, r)
    if len(a) < COMMON_MODE_MIN_PAIRS:
        return None
    return _stats.spearman(a, b)


def verify(
    payload: Dict[str, Any],
    authentic: Callable[[Dict[str, Any]], bool],
    store: Any,
    now: float,
    spot_checks: int = 3,
    allow_self: bool = False,
    rng: Optional[random.Random] = None,
) -> Dict[str, Any]:
    rej: List[str] = []
    warn: List[str] = []
    checks: Dict[str, Any] = {}
    rng = rng or random.Random(secrets.randbits(64))

    ch = payload.get("challenge") or {}
    plan = ch.get("plan") or {}
    nonce = str(ch.get("nonce", ""))
    results = payload.get("results") or {}
    session = payload.get("session") or {}

    if payload.get("format") != FORMAT or ch.get("format") != FORMAT:
        rej.append("bad_format")
    from ..attest import payload_digest  # local import: avoid cycle

    if payload.get("digest") != payload_digest(payload):
        rej.append("digest_mismatch")

    # ---- binding: authentic challenge, single-use nonce, time window ----------
    self_issued = ch.get("issuer") == "self"
    if self_issued:
        checks["self_issued"] = True
        if not allow_self:
            rej.append("self_issued_challenge")
    else:
        if not authentic(ch):
            rej.append("challenge_not_authentic")
        status = store.consume(nonce)
        if status == "reused":
            rej.append("nonce_reused")
        elif status == "unknown":
            rej.append("nonce_unknown")
    issued_at = float(ch.get("issued_at", 0))
    expires_at = float(ch.get("expires_at", 0))
    if now > expires_at:
        rej.append("challenge_expired")
    server_window = now - issued_at
    claimed = float(session.get("elapsed_ns") or 0) / 1e9
    checks["server_window_s"] = round(server_window, 3)
    checks["client_elapsed_s"] = round(claimed, 3)
    if not self_issued and claimed > server_window + CLOCK_SLACK_S:
        rej.append("claims_more_time_than_elapsed")

    # ---- per-module: exact parameters, ordering, plausibility -----------------
    if not plan:
        rej.append("no_plan")
        return _result(rej, warn, checks)
    order_end: List[Tuple[float, float, str]] = []
    total_dur = 0.0
    for mod in ("clock", "cache", "jitter", "simd"):
        mres = results.get(mod) or {}
        samples = mres.get("samples") or []
        expected = _plan_keys(plan, mod)
        got = [_sample_key(mod, s) for s in samples]
        frac = len(got) / len(expected) if expected else 1.0
        checks[f"{mod}_complete"] = round(frac, 3)
        if got != expected[: len(got)]:
            rej.append(f"{mod}_not_plan_prefix")
            continue
        if expected and frac < MIN_COMPLETE_FRACTION:
            (warn if mres.get("error") else rej).append(f"{mod}_incomplete")
        elif frac < 1.0:
            warn.append(f"{mod}_truncated")
        bad_params = sum(1 for s in samples if not _expected_param(plan, mod, s)[0])
        if bad_params:
            rej.append(f"{mod}_param_mismatch")
            continue
        t_i, d_i = _t0_idx(mod), _dur_idx(mod)
        last_end = -1.0
        overlap = False
        too_fast = 0
        for s in samples:
            t0, dur = float(s[t_i]), float(s[d_i])
            if t0 < last_end or dur <= 0:
                overlap = True
            last_end = t0 + dur
            total_dur += dur
            if dur < MIN_NS_PER_UNIT[mod] * _work_units(mod, s):
                too_fast += 1
        if overlap:
            rej.append(f"{mod}_timeline_inconsistent")
        if too_fast:
            rej.append(f"{mod}_implausibly_fast")
        if samples:
            order_end.append((float(samples[0][t_i]), last_end, mod))
        c = consistency(mod, samples)
        checks[f"{mod}_consistency"] = None if c is None else round(c, 3)
        if c is not None:
            if c < CONSISTENCY_HARD:
                rej.append(f"{mod}_durations_do_not_track_parameters")
            elif c < CONSISTENCY_SOFT:
                warn.append(f"{mod}_weak_parameter_tracking")
            elif c >= TOO_PERFECT and len(samples) >= 20:
                # Real timings always carry noise; rank-sorted synthetic ones don't.
                warn.append(f"{mod}_durations_perfectly_monotone")
        # Spot-check: re-execute a few random samples and compare results.
        if samples and spot_checks > 0:
            pick = rng.sample(range(len(samples)), min(spot_checks, len(samples)))
            if mod == "cache":  # bound verifier cost: prefer smaller buffers
                small = sorted(range(len(samples)), key=lambda i: int(samples[i][2]))
                pick = [small[0]] + rng.sample(small[: max(1, len(small) // 2)], 1)
            for i in pick:
                if _recompute(plan, mod, samples[i]) != samples[i][-1]:
                    rej.append(f"{mod}_result_mismatch")
                    break
    # Modules must have run in the plan's order, without overlapping.
    order_end.sort()
    ran = [m for _, _, m in order_end]
    want = [m for m in plan.get("order", []) if m in ran]
    if ran != want:
        rej.append("module_order_mismatch")
    for (_, e1, _), (s2, _, _) in zip(order_end, order_end[1:]):
        if s2 < e1:
            rej.append("modules_overlap")
            break
    elapsed_ns = float(session.get("elapsed_ns") or 0)
    if order_end and elapsed_ns < order_end[-1][1]:
        rej.append("session_shorter_than_samples")
    checks["sum_sample_s"] = round(total_dur / 1e9, 3)

    perfect = [w for w in warn if w.endswith("_durations_perfectly_monotone")]
    if len(perfect) >= 2:
        rej.append("synthetic_monotone_timings")

    cm = common_mode((results.get("jitter") or {}).get("samples") or [])
    checks["jitter_common_mode"] = None if cm is None else round(cm, 3)

    # ---- replay of an identical timing trace under a new nonce ----------------
    th = trace_hash(results)
    prev = store.trace_seen(th, nonce)
    if prev is not None:
        rej.append("timing_trace_replayed")
    checks["trace_hash"] = th[:16]
    return _result(rej, warn, checks)


def _result(rej: List[str], warn: List[str], checks: Dict[str, Any]) -> Dict[str, Any]:
    rej = sorted(set(rej))
    integrity = 0.0 if rej else max(0.0, 1.0 - 0.15 * len(set(warn)))
    return {
        "accepted": not rej,
        "integrity": round(integrity, 3),
        "rejections": rej,
        "warnings": sorted(set(warn)),
        "checks": checks,
    }

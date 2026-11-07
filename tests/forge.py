"""Attack helpers for replay tests: re-label a recorded trace onto a new challenge.

The attacker here is strong: it re-executes every kernel *for its result*
(so result spot-checks pass) and only lies about the timings.
"""

import copy
import random

from hwattest.attest import payload_digest
from hwattest.score.verify import _dur_idx, _recompute


def _keys(plan, mod):
    if mod == "cache":
        return [(i, r, it["size"], st) for i, it in enumerate(plan["cache"]["items"])
                for r, st in enumerate(it["steps"])]
    if mod == "clock":
        return [(i, n) for i, n in enumerate(plan["clock"]["work"])]
    return [(i, a, b) for i, (a, b) in enumerate(plan[mod]["schedule"])]


def _unit(mod, k):
    return k[3] if mod == "cache" else k[1] if mod == "clock" else k[2]


def _grp(mod, k):
    return k[2] if mod == "cache" else "all" if mod == "clock" else k[1]


def relabel(src, ch, mode="index", noise=0.0, seed=0):
    """mode='index': reuse durations in recorded order.
    mode='rank': per sub-kind, assign recorded durations by rank of the new
    work units (defeats naive correlation checks); ``noise`` adds multiplicative
    jitter to hide the perfect ordering."""
    rnd = random.Random(seed)
    p = {"challenge": ch, "client": src["client"], "session": copy.deepcopy(src["session"]),
         "results": copy.deepcopy(src["results"]), "share_raw": False, "format": src["format"]}
    plan = ch["plan"]
    t = 1000
    for mod in plan["order"]:
        old = src["results"][mod]["samples"]
        keys = _keys(plan, mod)
        durs = [s[_dur_idx(mod)] for s in old]
        if mode == "rank":
            pools = {}
            for s in old:
                okey = (s[2] if mod == "cache" else "all" if mod == "clock" else s[1])
                pools.setdefault(okey, []).append(s[_dur_idx(mod)])
            groups = {}
            for j, k in enumerate(keys):
                groups.setdefault(_grp(mod, k), []).append(j)
            assigned = [0] * len(keys)
            for g, idxs in groups.items():
                pool = sorted(pools.get(g) or durs)
                idxs = sorted(idxs, key=lambda j: _unit(mod, keys[j]))
                for r, j in enumerate(idxs):
                    q = int(r * (len(pool) - 1) / max(1, len(idxs) - 1))
                    assigned[j] = pool[q] * (1.0 + rnd.gauss(0, noise))
            durs = assigned
        new = []
        for j, k in enumerate(keys):
            d = max(1, int(durs[j % len(durs)]))
            s = list(k) + [t, d, None]
            s[-1] = _recompute(plan, mod, s)
            new.append(s)
            t += d + 500
        p["results"][mod]["samples"] = new
    p["session"]["elapsed_ns"] = t + 1000
    p["digest"] = payload_digest(p)
    return p

"""Near-duplicate machines and suspicious uniformity across one RP's submissions.

Generalises the earlier ROM-hash clustering idea (identical ROM dumps across
"different" machines = an emulator farm) from exact hashes to measured curves:

* **same machine**: fingerprint similarity >= ``same_machine`` threshold
  (calibrated from same-machine repeatability). Many accounts on one cluster =
  one physical box driving several identities (or VMs on one host, whose
  timing passes through and therefore clusters with the host).
* **suspiciously identical**: similarity so high it exceeds what repeated
  runs of a real machine achieve (``identical``), or an identical timing-trace
  hash: replay / synthesis / cloned traces.

Similarity is a weighted mean of per-feature normalised distances mapped
through exp(-d). Feature scales come from observed same-machine spread.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

GRID = [str(g) for g in range(13, 27)]
SIMD_OPS = ["adler32", "blake2b", "crc32", "md5", "memchr", "memcmp", "memcpy", "sha1",
            "sha256", "sha3_256", "sha512", "translate"]

# Per-feature scale = roughly 2x the same-machine spread seen in eval/ (local runs).
SCALES: Dict[str, float] = {
    "cache": 0.35,         # log1p(excess ns), per grid point
    "simd": 0.35,          # log2 throughput ratio vs memcpy
    "jit_ratio": 0.12,     # fp/int, branch/int, ldst/int
    "speed": 0.35,         # log(int per-op ns): load/frequency dependent -> wide
    "clock_read": 0.6,     # log(clock read p50); coarse (10 ns quantised on some hosts)
}
WEIGHTS: Dict[str, float] = {
    "cache": 3.0, "simd": 3.0, "jit_ratio": 1.5, "speed": 0.5, "clock_read": 1.0,
    "flags": 1.5, "cpus": 0.5,
}

DEFAULT_SAME_MACHINE = 0.5
DEFAULT_IDENTICAL = 0.995


def fingerprint(feats: Dict[str, Any]) -> Dict[str, Any]:
    """Compact, comparable vector of the features that identify a machine."""
    cache = (feats.get("cache") or {}).get("excess_grid") or {}
    simd = feats.get("simd") or {}
    prof = simd.get("profile") or {}
    jit = feats.get("jitter") or {}
    vm = feats.get("vm") or {}
    clock = feats.get("clock") or {}
    int_op = (jit.get("int") or {}).get("per_op_ns")
    rd = clock.get("read_p50_ns")
    return {
        "arch": vm.get("arch"),
        "vendor": vm.get("cpu_vendor"),
        "cpus": vm.get("logical_cpus"),
        "cache": {g: (math.log1p(max(0.0, cache[g])) if cache.get(g) is not None else None)
                  for g in GRID},
        "simd": {op: prof.get(op) for op in SIMD_OPS},
        "jit_ratio": {k: jit.get(f"ratio_{k}_int") for k in ("fp", "branch", "ldst")},
        "speed": math.log(int_op) if int_op and int_op > 0 else None,
        "clock_read": math.log(rd) if rd and rd > 0 else None,
        "flags": sorted(simd.get("flags") or []),
    }


POINT_CAP = 4.0


def _vec_dist(a: Dict[str, Any], b: Dict[str, Any], scale: float) -> Optional[float]:
    """Median of capped per-point distances.

    Median + cap keeps one contention-sensitive region (e.g. the shared L3
    while another process thrashes it) from dominating the comparison.
    """
    ds = [
        min(POINT_CAP, abs(a[k] - b[k]) / scale)
        for k in a
        if a.get(k) is not None and b.get(k) is not None
    ]
    if not ds:
        return None
    ds.sort()
    m = len(ds) // 2
    return ds[m] if len(ds) % 2 else (ds[m - 1] + ds[m]) / 2


def similarity(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[float, Dict[str, float]]:
    """Return (similarity in [0,1], per-component distances)."""
    if a.get("arch") != b.get("arch") or a.get("vendor") != b.get("vendor"):
        return 0.0, {"arch_or_vendor": math.inf}
    parts: Dict[str, float] = {}
    for comp in ("cache", "simd", "jit_ratio"):
        d = _vec_dist(a[comp], b[comp], SCALES[comp])
        if d is not None:
            parts[comp] = d
    for comp in ("speed", "clock_read"):
        if a.get(comp) is not None and b.get(comp) is not None:
            parts[comp] = abs(a[comp] - b[comp]) / SCALES[comp]
    fa, fb = set(a.get("flags") or []), set(b.get("flags") or [])
    if fa or fb:
        parts["flags"] = 3.0 * (1.0 - len(fa & fb) / len(fa | fb))
    if a.get("cpus") and b.get("cpus"):
        parts["cpus"] = 0.0 if a["cpus"] == b["cpus"] else 1.0
    if not parts:
        return 0.0, parts
    wsum = sum(WEIGHTS[k] for k in parts)
    d = sum(WEIGHTS[k] * v for k, v in parts.items()) / wsum
    return math.exp(-d), {k: round(v, 3) for k, v in parts.items()}


class _UF:
    def __init__(self, n: int) -> None:
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def cluster(
    items: Sequence[Dict[str, Any]],
    same_machine: float = DEFAULT_SAME_MACHINE,
    identical: float = DEFAULT_IDENTICAL,
) -> List[Dict[str, Any]]:
    """Cluster submissions of one relying party.

    ``items``: dicts with ``id``, ``account`` (RP-side identity, optional),
    ``fp`` (from :func:`fingerprint`) and optional ``trace_hash``.
    Returns one result per item, same order.
    """
    n = len(items)
    uf = _UF(n)
    best: List[Tuple[float, Optional[int]]] = [(0.0, None)] * n
    links: List[Tuple[int, int, float]] = []
    flags: List[List[str]] = [[] for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            s, _ = similarity(items[i]["fp"], items[j]["fp"])
            if s > best[i][0]:
                best[i] = (s, j)
            if s > best[j][0]:
                best[j] = (s, i)
            if s >= same_machine:
                uf.union(i, j)
                links.append((i, j, s))
            if s >= identical:
                for k in (i, j):
                    if "suspiciously_identical_fingerprint" not in flags[k]:
                        flags[k].append("suspiciously_identical_fingerprint")
            th_i, th_j = items[i].get("trace_hash"), items[j].get("trace_hash")
            if th_i and th_i == th_j:
                for k in (i, j):
                    if "identical_timing_trace" not in flags[k]:
                        flags[k].append("identical_timing_trace")

    groups: Dict[int, List[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)
    link_by_root: Dict[int, List[float]] = {}
    for i, _j, s in links:
        link_by_root.setdefault(uf.find(i), []).append(s)

    out: List[Dict[str, Any]] = []
    for i, it in enumerate(items):
        root = uf.find(i)
        members = groups[root]
        # Named after its earliest member, so ids are stable as clusters grow.
        cid = hashlib.sha256(str(items[members[0]]["id"]).encode()).hexdigest()[:12]
        accounts = {items[m].get("account") for m in members if items[m].get("account")}
        sims = link_by_root.get(root, [])
        conf = (sum(sims) / len(sims)) if sims else 0.0
        bs, bj = best[i]
        res: Dict[str, Any] = {
            "id": it["id"],
            "cluster_id": cid,
            "cluster_size": len(members),
            "distinct_accounts": len(accounts),
            "confidence": round(conf, 3),
            "nearest": None if bj is None else {"id": items[bj]["id"], "similarity": round(bs, 3)},
            "flags": list(flags[i]),
        }
        if len(members) > 1 and len(accounts) > 1:
            res["flags"].append("same_machine_multiple_accounts")
        out.append(res)
    return out

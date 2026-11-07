"""Small, dependency-free robust statistics used by measurement and scoring.

Everything here is pure Python so the core works on any CPython >= 3.9
(including slow vintage machines). numpy is never required.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple


def mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def median(xs: Sequence[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    if n % 2:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def quantile(xs: Sequence[float], q: float) -> float:
    """Linear-interpolated quantile, q in [0, 1]."""
    if not xs:
        return 0.0
    s = sorted(xs)
    if len(s) == 1:
        return float(s[0])
    pos = q * (len(s) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(s) - 1)
    frac = pos - lo
    return s[lo] * (1.0 - frac) + s[hi] * frac


def stdev(xs: Sequence[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (n - 1))


def cv(xs: Sequence[float]) -> float:
    m = mean(xs)
    return stdev(xs) / m if m else 0.0


def mad(xs: Sequence[float]) -> float:
    """Median absolute deviation (unscaled)."""
    if not xs:
        return 0.0
    m = median(xs)
    return median([abs(x - m) for x in xs])


def robust_cv(xs: Sequence[float]) -> float:
    """1.4826 * MAD / median: a CV that ignores preemption spikes."""
    m = median(xs)
    return 1.4826 * mad(xs) / m if m else 0.0


def skewness(xs: Sequence[float]) -> float:
    n = len(xs)
    if n < 3:
        return 0.0
    m = mean(xs)
    s = stdev(xs)
    if s == 0:
        return 0.0
    return sum(((x - m) / s) ** 3 for x in xs) / n


def lag1_autocorr(xs: Sequence[float]) -> float:
    n = len(xs)
    if n < 3:
        return 0.0
    m = mean(xs)
    den = sum((x - m) ** 2 for x in xs)
    if den == 0:
        return 0.0
    num = sum((xs[i] - m) * (xs[i - 1] - m) for i in range(1, n))
    return num / den


def _ranks(xs: Sequence[float]) -> List[float]:
    order = sorted(range(len(xs)), key=lambda i: xs[i])
    ranks = [0.0] * len(xs)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and xs[order[j + 1]] == xs[order[i]]:
            j += 1
        r = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = r
        i = j + 1
    return ranks


def pearson(xs: Sequence[float], ys: Sequence[float]) -> float:
    n = min(len(xs), len(ys))
    if n < 3:
        return 0.0
    mx, my = mean(xs[:n]), mean(ys[:n])
    sxy = sum((xs[i] - mx) * (ys[i] - my) for i in range(n))
    sxx = sum((xs[i] - mx) ** 2 for i in range(n))
    syy = sum((ys[i] - my) ** 2 for i in range(n))
    if sxx == 0 or syy == 0:
        return 0.0
    return sxy / math.sqrt(sxx * syy)


def spearman(xs: Sequence[float], ys: Sequence[float]) -> float:
    n = min(len(xs), len(ys))
    if n < 3:
        return 0.0
    return pearson(_ranks(xs[:n]), _ranks(ys[:n]))


def theil_sen(
    xs: Sequence[float], ys: Sequence[float], max_pairs: int = 20000
) -> Tuple[float, float]:
    """Robust line fit y = a + b*x. Returns (intercept, slope).

    Uses all pairs up to ``max_pairs`` (deterministic subsampling beyond that).
    """
    n = min(len(xs), len(ys))
    if n < 2:
        return (ys[0] if n else 0.0), 0.0
    slopes: List[float] = []
    total = n * (n - 1) // 2
    step = max(1, total // max_pairs)
    idx = 0
    for i in range(n):
        for j in range(i + 1, n):
            if idx % step == 0:
                dx = xs[j] - xs[i]
                if dx != 0:
                    slopes.append((ys[j] - ys[i]) / dx)
            idx += 1
    if not slopes:
        return median(ys[:n]), 0.0
    b = median(slopes)
    a = median([ys[i] - b * xs[i] for i in range(n)])
    return a, b


def linreg(xs: Sequence[float], ys: Sequence[float]) -> Tuple[float, float]:
    """Ordinary least squares. Returns (intercept, slope)."""
    n = min(len(xs), len(ys))
    if n < 2:
        return (ys[0] if n else 0.0), 0.0
    mx, my = mean(xs[:n]), mean(ys[:n])
    sxx = sum((xs[i] - mx) ** 2 for i in range(n))
    if sxx == 0:
        return my, 0.0
    b = sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / sxx
    return my - b * mx, b


def summarize(xs: Sequence[float]) -> Dict[str, float]:
    """Distribution summary (not a pass/fail)."""
    if not xs:
        return {"n": 0}
    return {
        "n": float(len(xs)),
        "min": float(min(xs)),
        "p01": quantile(xs, 0.01),
        "p10": quantile(xs, 0.10),
        "p50": median(xs),
        "p90": quantile(xs, 0.90),
        "p99": quantile(xs, 0.99),
        "max": float(max(xs)),
        "mean": mean(xs),
        "cv": cv(xs),
        "robust_cv": robust_cv(xs),
        "skew": skewness(xs),
        "lag1": lag1_autocorr(xs),
    }


def gcd_list(xs: Sequence[int]) -> int:
    g = 0
    for x in xs:
        if x:
            g = math.gcd(g, int(x))
            if g == 1:
                break
    return g


def interp(x: float, xs: Sequence[float], ys: Sequence[float]) -> Optional[float]:
    """Piecewise-linear interpolation; clamps to the end values. xs sorted ascending."""
    if not xs:
        return None
    if x <= xs[0]:
        return float(ys[0])
    if x >= xs[-1]:
        return float(ys[-1])
    for i in range(1, len(xs)):
        if x <= xs[i]:
            x0, x1 = xs[i - 1], xs[i]
            y0, y1 = ys[i - 1], ys[i]
            if x1 == x0:
                return float(y1)
            t = (x - x0) / (x1 - x0)
            return y0 + t * (y1 - y0)
    return float(ys[-1])


def clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def noisy_or(ps: Sequence[float]) -> float:
    """Combine independent pieces of evidence: 1 - prod(1 - p)."""
    out = 1.0
    for p in ps:
        out *= 1.0 - clamp01(p)
    return 1.0 - out

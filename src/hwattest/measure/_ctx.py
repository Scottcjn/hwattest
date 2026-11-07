"""Shared measurement context: session clock, checkpoints, deadlines."""

from __future__ import annotations

import time
from typing import List, Optional


class Context:
    """Holds the session start time and periodic clock checkpoints.

    A checkpoint is ``[perf_rel_ns, mono_rel_ns]`` relative to session start.
    Clocks that would allow precise cross-site linking (MONOTONIC_RAW vs
    MONOTONIC slew) are only used client-side to derive a rounded ppm figure.
    """

    def __init__(self, master_seed: int, module_budget_s: float = 60.0) -> None:
        self.master_seed = master_seed
        self.module_budget_ns = int(module_budget_s * 1e9)
        self.t0 = time.perf_counter_ns()
        self.m0 = time.monotonic_ns()
        self._raw_id: Optional[int] = getattr(time, "CLOCK_MONOTONIC_RAW", None)
        self.checkpoints: List[List[int]] = []
        # (mono_ns, raw_ns) pairs for the slew estimate; never leave the machine.
        self._slew_pairs: List[List[int]] = []
        self.checkpoint()

    def rel(self) -> int:
        return time.perf_counter_ns() - self.t0

    def checkpoint(self) -> None:
        p = time.perf_counter_ns() - self.t0
        m = time.monotonic_ns() - self.m0
        self.checkpoints.append([p, m])
        if self._raw_id is not None:
            try:
                a = time.monotonic_ns()
                r = time.clock_gettime_ns(self._raw_id)
                b = time.monotonic_ns()
                self._slew_pairs.append([(a + b) // 2, r])
            except (OSError, AttributeError):
                self._raw_id = None

    def deadline(self) -> int:
        """Absolute perf_counter_ns deadline for a module starting now."""
        return time.perf_counter_ns() + self.module_budget_ns

    def slew_ppm(self) -> Optional[float]:
        """MONOTONIC (NTP-disciplined) vs MONOTONIC_RAW (crystal) rate, in ppm.

        This is the kernel's current frequency correction for the local
        oscillator. Rounded to 0.25 ppm to limit cross-site linkability.
        """
        pts = self._slew_pairs
        if len(pts) < 2:
            return None
        dm = pts[-1][0] - pts[0][0]
        dr = pts[-1][1] - pts[0][1]
        if dr <= 0 or dm < 1_000_000_000:  # need >= 1 s of baseline
            return None
        ppm = (dm - dr) / dr * 1e6
        return round(ppm * 4) / 4

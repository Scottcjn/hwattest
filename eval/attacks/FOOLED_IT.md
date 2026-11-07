# How we fooled it — the public attack log

hwattest is a **probabilistic** score, not a proof. The honest way to run a
project like this is in the open: every attack we or anyone else lands on it
goes here, with enough detail to reproduce, whether or not it is fixed. A short
log that says "nothing gets through" would be a lie by omission.

**If you get a fake past it, we want to add your entry.** Send a reproduce
recipe (ideally a test like `tests/test_replay.py`) and it goes in the table
with credit. This log is seeded with what v0.1 already knows.

Legend: **OPEN** = passes verification today. **MITIGATED** = not fully blocked
but made harder/visible. **BLOCKED** = rejected by a hard check with a named
reason.

| # | Attack | Status (v0.1) | Caught by | Reproduce |
|---|---|---|---|---|
| 1 | Re-submit a recorded payload verbatim | BLOCKED | `nonce_reused` | `test_replay.py::resubmit` |
| 2 | Recorded samples under a fresh challenge | BLOCKED | param/result mismatch, `claims_more_time_than_elapsed`, `timing_trace_replayed` | `test_replay.py::swap_challenge` |
| 3 | Re-label recorded timings onto the new plan, re-executing every kernel for its real result | BLOCKED | `*_durations_do_not_track_parameters`, `simd_implausibly_fast` | `test_replay.py::relabel_index` |
| 4 | Same, timings assigned by **rank** of the new parameters (monotone) | BLOCKED | `synthetic_monotone_timings` (rank-perfect in ≥2 modules) | `test_replay.py::relabel_rank` |
| 5 | **Rank-mapped timings + ~12% multiplicative noise** | **OPEN** | — (see below) | `eval/replay.py`; `tests/test_replay.py::test_known_bypass_rank_relabel_with_noise_is_not_detected` |
| 6 | Fully patched client that fabricates every sample from a model of the target CPU | OPEN (by design) | — | software-only measurement limit |
| 7 | KVM guest with CPUID hypervisor bit cleared + SMBIOS spoofed to Dell (`kvm_hidden`) | MITIGATED | leftover `virtio` PCI, `kvm-clock` clocksource, `steal_ticks` — **not timing** | `eval/vm/run_guest.sh kvm_hidden` |
| 8 | QEMU TCG with device tells also scrubbed (`tcg_hardened`) | BLOCKED | timing: memcpy-vs-SHA gap, SHA256-vs-SHA512, clock-read cost, oscillator ppm | `eval/vm/run_guest.sh tcg_hardened` |
| 9 | `LD_PRELOAD` / ctypes hook on the clock source | OPEN (untested) | — | not yet attempted |
| 10 | Rewrite `/proc/cpuinfo` / DMI (container, patched kernel) | MITIGATED | those fields are treated as *features*, not verdicts; timing evidence still used | — |

## Attack #5 in detail — the most important open hole

An attacker who **re-executes every kernel honestly** (so the results verify),
but **sources the timing distributions from a recording of a real machine**,
mapped onto the new plan's parameters by rank and then perturbed with ~12%
multiplicative noise, **passes v0.1 verification**. The noise defeats the
rank-perfection check (attack #4) without pushing any duration off the
parameter-monotone trend far enough to trip
`*_durations_do_not_track_parameters`, and every re-executed result is correct,
so nothing hard-rejects.

**Why clustering does not save us here.** In the local replay run (n=10) the
forgery's fingerprint similarity to its own source machine was **0.20–0.51**
(median ~0.35) — mostly *below* the 0.5 same-machine threshold. So the forged
submission does not even reliably cluster back to the machine it was copied
from; clustering is a weak mitigation at best, not a fix.

Reproduce:

```bash
python3 eval/replay.py --trials 10 --out eval/results/replay.json
# row relabel_rank_noise: accepted 10/10
# accepted_forgery_similarity_to_source: ~0.20..0.51
```

**Candidate directions (not yet built; do not claim any as done):**
higher-moment timing-shape tests (the real per-op distribution is not a noisy
rank curve — tails and multi-modality differ); cross-module coupling the forger
has to keep consistent under one nonce; raising the per-challenge parameter
entropy so a rank map carries less information; and ultimately the optional TPM
/ platform-attestation path for callers who need more than software timing.
None of these is implemented in v0.1.

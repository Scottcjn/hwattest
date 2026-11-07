# hwattest v0.1.0

**Is a benchmark result from a real, distinct physical machine — or a VM, an
emulator, or a replayed trace?** hwattest attaches a *probabilistic*
hardware-authenticity score, with human-readable reasons, to a submission and
binds it to that specific result so the score can't be moved onto a different
number. The client measures; a self-hostable server scores and clusters.

This is a first public cut (v0.1, alpha). It is deliberately honest about what
it can and cannot prove.

## What's in it
- **`hwattest measure`** — client microbenchmarks (clock/oscillator drift,
  cache-latency curve, instruction-path jitter, SIMD timing, VM/hypervisor
  indicators as *features* not verdicts), returning distributions, not pass/fail.
- **Challenge–response** — server issues a nonce + randomized parameters; the
  result is bound to the nonce and to the benchmark payload digest, so a
  recording of one machine can't be reattached to another number.
- **Scorer + clustering** — transparent heuristics with reasons; near-duplicate
  and suspicious-uniformity detection across submissions.
- **Privacy by construction** — derived features only; `hwattest inspect` shows
  exactly what would leave the machine. The published dataset was run through
  `eval/verify_no_identifiers.py` (fail-closed) and carries no MACs, serials,
  hostnames, machine-ids, or CPU model strings.

## Honest limits (read these first)
- Software-only measurement runs on the machine being judged. A determined
  attacker can patch the client or replay traces. Defenses raise cost; they do
  not make forgery impossible.
- **One documented bypass passes today**: rank-relabel + ~12% injected noise
  (attack #5 in `eval/attacks/FOOLED_IT.md`). It is disclosed on purpose, with
  its status, alongside the other nine attacks.
- One real machine can still drive many accounts. This detects machine
  *distinctness and realness*, not human intent or quality of work.
- Not for gating essential services. Intended for opt-in, low-stakes uses:
  benchmark-leaderboard realness, bounty anti-sybil, research datasets.

## Evaluation (single-host v0.1)
Numbers trace to `eval/results/` and reproduce via the block in the README.
- Separation on the current labeled set reported with its ROC/AUC in the README;
  every claimed number has a reproduce command.
- **One physical host** so far (bare metal / KVM / hidden-KVM / QEMU-TCG /
  hardened-TCG / Docker control / replay). No multi-machine fleet yet — see
  `eval/FLEET_PLAN.md`. Treat cross-machine similarity claims as unproven until
  the fleet run lands.
- Dataset: 41 records across 8 files + 2 results files, **verified free of
  machine identifiers**.

## Install / run
```bash
pip install hwattest            # or: pip install -e . from a checkout
hwattest measure --rp demo      # measure + score locally
hwattest inspect                # show exactly what would be sent
```
Tests: `python -m pytest` (53 tests). Lint/type: `ruff` + `mypy --strict` clean.

## Not included / not implied
No token, no coin, no on-chain anything. hwattest is a measurement-and-scoring
library; it makes no claim of value and gates nothing by itself.

---
License: Apache-2.0. See `eval/DATASHEET.md` and `eval/attacks/FOOLED_IT.md`
for the dataset record and the standing "how we fooled it" log.

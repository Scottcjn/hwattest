# hwattest

**Is this benchmark result real?** One command, ~90 seconds: *how likely is it
that this number was produced on a real, distinct physical machine — and not on
a VM, an emulator, a replayed trace, or a clone of a machine we have already
seen — with the reasons spelled out.*

A tok/s or a Geekbench score you read off the internet is self-reported. It is
trivial to post a fast number that a cloud VM, a binary-translation emulator, or
a recording of someone else's machine produced. hwattest attaches a
**probabilistic hardware-authenticity score with reasons** to a result, so a
leaderboard or a bounty program can tell "measured on real hardware, score 0.97"
from "unverifiable." The client measures; a server you run yourself scores and
clusters. The output is a set of scores with reasons, **never a yes/no proof.**

It is eval-first on purpose: the numbers below ([Evaluation](#evaluation-so-far-one-machine))
and the open hole we already know about ([Known open bypasses](#known-open-bypasses-v01))
are the whole credibility story. If you want the bottom line before the pitch:
on one machine the signals separate cleanly (AUC 1.00, 0 false-rejects on 25
real runs), **and** a rank-relabel-plus-noise forgery passes v0.1 verification
today. Both are true; both are below.

Version 0.1. Apache-2.0. Python 3.9+ standard library only (numpy is not
needed). There is no token, coin, or blockchain anywhere in this project.

## Honest limits (read these first)

- **Software-only measurement runs on the machine being judged.** A determined
  attacker can patch the client or synthesize traces. The challenge-response
  protocol raises the cost of that (fresh randomized parameters, result
  re-execution, timing consistency checks), it does not make it impossible.
  One such bypass is known, implemented as a test, and **passes** v0.1
  verification: an attacker who re-executes every kernel for its result,
  re-maps a real machine's recorded timings onto the new parameters by rank and
  adds noise (see *Known open bypasses*).
- **It detects machine distinctness and realness, not human intent or the
  quality of anyone's work.** One real machine can still drive many accounts;
  the clustering is there to make that visible, not to prevent it.
- **Fingerprints can track people.** By default no raw identifier leaves the
  machine (no DMI strings, no CPU model string, no MAC, no serials), only
  per-challenge timing samples, derived features and a machine ID salted per
  relying party. But the measured curves themselves are fairly
  machine-specific, so two colluding relying parties could try to link the
  same machine by comparing feature vectors. Treat submissions as personal
  data.
- **Not for gating essential services.** Intended for opt-in, low-stakes uses:
  bounty anti-sybil, benchmark leaderboards, research datasets.
- **The evaluation so far is one physical machine** (see *Evaluation*). Whether
  different machines of the same model separate, and whether slow vintage CPUs
  trip the emulator heuristics, has **not been measured yet**. Thresholds are
  provisional.
- A VM that hides its tells (CPUID hypervisor bit off, SMBIOS spoofed) and runs
  under hardware virtualization times like the host. Our timing features do
  not separate it; what still catches it are the leftover device-level tells,
  and those can be removed too.
- The optional TPM quote uses a fresh attestation key **not chained to the
  endorsement key**: a valid quote shows that *some* TPM (possibly a VM's
  virtual TPM) signed the nonce. It is reported, not scored.

## Evaluation (so far: ONE machine)

Everything below was collected on **one** host: the HP Victus laptop (AMD
Ryzen 7 8845HS, 16 threads, Linux 6.17). Treat it as a sanity check that the
signals separate on this machine, **not** as a general accuracy claim. The
cross-machine questions are unanswered until the fleet runs (`eval/FLEET_PLAN.md`).

Dataset: `eval/data/local/` (41 records; derived features + per-sample timings,
**no machine identifiers** — enforced by `eval/verify_no_identifiers.py` and a
CI test, documented in [`eval/DATASHEET.md`](eval/DATASHEET.md)). Reproduce the
numbers end to end:

```bash
PYTHON=../.venv/bin/python eval/run_local.sh          # re-collect (this machine)
python3 eval/evaluate.py eval/data/local/*.jsonl \
        --out eval/results/local_metrics.json         # ROC/AUC, FPR, confusion
python3 eval/replay.py --trials 10 \
        --out eval/results/replay.json                # the replay/forgery attacks
python3 eval/verify_no_identifiers.py 'eval/data/local/*.jsonl'  # privacy gate
```

Every attempted attack and its status lives in the public
[`eval/attacks/FOOLED_IT.md`](eval/attacks/FOOLED_IT.md) log — including the one
that works (below). If you land a new one, send a reproduce recipe and it goes
in the table with credit.

| Group | n | how |
|---|---|---|
| bare_metal / idle | 10 | the Victus, unloaded |
| bare_metal / load8 | 5 | + 8 busy-loop processes |
| bare_metal / load16 | 5 | + 16 busy-loop processes (over-subscribed) |
| container / docker | 5 | `python:3.12-slim`, `--network none` (non-VM control) |
| vm / kvm | 5 | QEMU/KVM guest, `-cpu host` (stock VM) |
| vm / kvm_hidden | 5 | QEMU/KVM, CPUID hypervisor bit off + SMBIOS spoofed to Dell |
| emulator / tcg | 3 | QEMU full-system TCG (binary translation) |
| emulator / tcg_hardened | 3 | TCG + hypervisor bit off + SMBIOS/CPU-name spoofed |

**Classification (n=41).** Positives for `real_hardware` = bare_metal +
container (25); negatives = vm + emulator (16).

- AUC `real_hardware` = **1.00**, AUC `vm` = **1.00**, AUC `emulator` = **1.00**.
- FPR on real hardware @0.5 = **0.0** (0/25 real runs scored not-real, including
  the over-subscribed load16 runs); fakes accepted as real @0.5 = **0.0** (0/16).
- Confusion (argmax rule, true -> predicted): every group classified correctly,
  including `kvm_hidden` -> vm (caught by leftover virtio/clocksource/steal-time
  tells, *not* timing) and both TCG variants -> emulator.

Caveat: these are tiny per-class counts (3-10) on one CPU, and the VM/emulator
guests all expose device-level tells. A VM that scrubs **every** device tell
and runs under KVM is expected to score as real hardware here (see limits).

**Challenge-response / replay (`eval/replay.py`, standard profile, 10 trials).**

| Attack | Accepted | Rejected | Why |
|---|---|---|---|
| genuine fresh run | 10 | 0 | (false-reject rate 0/10) |
| resubmit recorded payload | 0 | 10 | `nonce_reused` |
| recorded samples, new challenge | 0 | 10 | param/result mismatch, `claims_more_time_than_elapsed`, trace replay |
| re-label timings, results re-executed | 0 | 10 | `*_durations_do_not_track_parameters`, `simd_implausibly_fast` |
| re-label by rank of new params | 0 | 10 | `synthetic_monotone_timings` |
| re-label by rank **+ 12% noise** | **10** | 0 | **open bypass** (above); fingerprint sim to source 0.20-0.51 |

**Same-machine repeatability** (all groups are the same physical host; higher =
more similar). Idle-to-idle fingerprint similarity median **0.766**
(0.41-0.89, n=45), 97.8% of pairs >= the 0.5 cluster threshold. Real-vs-emulator
similarity median **~0.08** (never above 0.12) - cleanly separated. CPU load
moves the fingerprint a lot (idle-to-load16 median 0.38), which is why the
same-machine threshold is low and why `speed` is weighted lightly; this is a
known weakness for clustering a machine measured idle against itself under heavy
load, to be characterised across the fleet.


## Known open bypasses (v0.1)

| Attack | Status |
|---|---|
| Re-submit a recorded payload | rejected (`nonce_reused`) |
| Recorded samples under a new challenge | rejected (parameter / result mismatch) |
| Re-label recorded timings onto a new plan, re-executing every kernel for its result | rejected (`*_durations_do_not_track_parameters`) |
| Same, timings assigned by rank of the new parameters | rejected (`synthetic_monotone_timings`) |
| Same, rank-mapped **plus ~12% noise** | **passes verification** (test `test_known_bypass_rank_relabel_with_noise_is_not_detected`). Weak mitigation only: in the local replay run the forgery's fingerprint similarity to its source was 0.20-0.51 (median ~0.35, n=10), i.e. mostly *below* the 0.5 same-machine threshold - so clustering does **not** reliably catch it either. This is the most important open hole in v0.1. |
| Patched client that fabricates everything from a model | not detected by design limits of software-only measurement |
| VM with CPUID hypervisor bit cleared and SMBIOS spoofed (KVM) | see *Evaluation*: caught only by leftover device tells |
| `LD_PRELOAD` / ctypes hooks on the clock | not detected |
| `/proc/cpuinfo` / DMI rewritten (containers, patched kernels) | features, not verdicts; timing evidence is still used |

These were designed against the bypass list in the earlier fingerprint
security review this work descends from (client-side trust, wide tolerances,
client-supplied serials, low field thresholds, hookable timers, falsifiable
`/proc/cpuinfo`): no client-reported pass/fail is trusted, every statistic is
recomputed server-side from per-sample data, no client-supplied serial is used
as evidence, and the remaining client-side-trust limits are stated above.

## How it works

### Measurements (client, `hwattest/measure/`)
All driven by a **plan** the server randomizes per challenge (buffer sizes,
loop counts, op sizes, interleaving and module order). Every sample records
`(index, parameters, start_ns, duration_ns, result)`; `result` is the output
of a deterministic, seed-derived kernel, so the server can re-execute it.

| Module | What it measures | Typical signal |
|---|---|---|
| `clock` | back-to-back clock-read cost distribution; fixed hashing work; MONOTONIC vs MONOTONIC_RAW frequency correction (rounded to 0.25 ppm); `adjtimex` read-only | emulated timers: ~1.6 us reads vs ~40 ns; >200 ppm "crystal" |
| `cache` | random pointer-chase latency vs working-set size (4 KiB..64 MiB), one random cycle per buffer | L1/L2/L3/TLB/DRAM knees; contention-sensitive |
| `jitter` | int / fp / branch / load-store loops with random counts | per-op cost, residual noise, tail, ratios |
| `simd` | throughput of native primitives Python links against (OpenSSL hashes, zlib, libc memcpy/memchr/memcmp, scalar contrasts) + SIMD-relevant CPU flags | under binary translation vector memcpy collapses toward hash speed; SHA-NI emulated in software |
| `vmind` | CPUID hypervisor bit, DMI tokens, paravirtual clocksource, virtio/QEMU/VMware PCI vendors, hypervisor MAC OUIs on bus NICs, steal time, systemd-detect-virt, container markers, macOS `kern.hv_vmm_present` | reported as features with categories, never raw strings |
| `tpm` | optional TPM 2.0 quote via tpm2-tools over the nonce | off unless requested; skipped cleanly without tools/device access |

Each module has a 60 s budget and stops early (reporting a truncated prefix
of the plan) instead of failing. The default plan takes ~3 s on a 2024
laptop and ~35 s under QEMU TCG emulation.

### Verification (server, `hwattest/score/verify.py`)
Hard rejections: bad digest; challenge MAC invalid (client-chosen plan);
nonce unknown/reused; expired; client claims more run time than the server
observed between issue and submit; samples not exactly the plan's
parameters/prefix; overlapping or out-of-order timeline; faster than
physically plausible per unit of work; re-executed kernel results differ
(spot checks); duration does not track the requested work
(Spearman < 0.2); rank-perfect timings in >= 2 modules; identical timing
trace seen before. Soft warnings lower `integrity` by 0.15 each.

### Scoring (`hwattest/score/scorer.py`)
Transparent heuristics. Every piece of evidence is a reason
`{dimension, feature, value, weight, text}`; a dimension's score is the
noisy-OR of its evidence weights.

- `vm` = noisy-OR of VM indicator weights (e.g. CPUID hypervisor bit 0.9,
  paravirtual clocksource 0.85, virtio PCI 0.6, steal time 0.6).
- `emulator` = noisy-OR of timing evidence: memcpy-vs-SHA-256 gap < 3 octaves,
  SHA-256 not faster than SHA-512 on a CPU that claims SHA instructions,
  clock read > 0.5 us on a TSC clocksource, > 200 ppm oscillator correction,
  and (weak, because slow real CPUs share it) a small DRAM-latency to
  interpreter-speed ratio.
- `container` is informational: a container on bare metal is real hardware.
- `integrity` comes from verification (0 if rejected; 0.3 for summary-only
  submissions, which cannot be verified).
- `real_hardware = (1 - noisyOR(vm, emulator)) x integrity x plausibility`
  (plausibility drops for a flat cache curve or implausibly uniform timings).

### Clustering (`hwattest/cluster/cluster.py`)
Per relying party. A fingerprint (cache excess curve on a fixed log grid,
median-centred SIMD profile, jitter ratios, interpreter speed, clock-read
cost, SIMD flags, CPU count) is compared with a weighted mean of *median,
capped* per-component distances mapped through `exp(-d)`. Pairs above
`same_machine` (0.5) join one cluster (single link); clusters with several
accounts are flagged `same_machine_multiple_accounts`. Pairs above 0.995, or
with an identical timing-trace hash, are flagged as suspiciously identical:
this generalizes the earlier ROM-hash idea (identical ROM dumps across
"different" machines = emulator farm) from exact hashes to measured curves.
VMs on one host time like the host and therefore tend to cluster with it,
which is what you want against a VM farm.

## Privacy

- **Local-only by default.** `hwattest measure` without `--server` writes the
  payload to stdout/a file and sends nothing. No network traffic happens during
  measurement (the earlier cloud-metadata probe was removed).
- **What is sent** (default): the challenge echo, per-challenge-sample
  timings/results (needed to verify the run), derived features (VM indicator
  *categories*, SIMD-relevant flags, CPU vendor, arch, logical CPU count,
  clocksource name, rounded ppm figures) and `machine_id_rp`.
- **What stays local** unless `--share-raw`: DMI vendor/product/board/BIOS
  strings, the CPU model string, the full CPU flag list. MACs, serials,
  hostnames and the raw clock-read deltas are never collected into the payload.
- **`--summary`** sends only client-computed features, no per-sample data; the
  server marks such a submission unverifiable (integrity 0.3).
- **`machine_id_rp`** = `HMAC-SHA256(local secret, "hwattest-machine-id/v1|" + rp_id + "|" + /etc/machine-id)`.
  Different for every relying party, so IDs cannot be joined across RPs; the
  secret lives in `~/.config/hwattest/secret` (0600); delete it to rotate.
  `--no-id` omits it. It is a continuity convenience the client controls,
  **not** anti-sybil evidence.
- **`hwattest inspect`** runs the measurement and prints exactly the payload
  that would be sent, plus a list of what is kept local. Nothing is sent;
  `--save f.json` then `hwattest measure --payload f.json --server URL`
  submits that exact file.
- **Retention (server):** submissions store scores, reasons, the derived
  fingerprint vector, cluster id, `machine_id_rp`, optional account name and
  bound hash. Per-sample timings and `--share-raw` fields are **not stored**.
  Everything (submissions, nonces, trace hashes) is purged after
  `--retention-days` (default 30).

## Quickstart

```bash
pip install .            # or run from a checkout: PYTHONPATH=src python3 -m hwattest.cli ...
hwattest inspect --pretty            # see exactly what would be sent; sends nothing
hwattest measure --out me.json       # local only
hwattest score me.json               # offline scores + reasons

# self-hosted service (binds 127.0.0.1; put TLS in front to expose it)
hwattest serve --rp-id my-bounty --data-dir ./hwattest-data --admin-token-file token.txt
hwattest measure --server http://127.0.0.1:8787 --rp my-bounty --account alice
```

**Benchmark leaderboards (the main use).** Bind the result to the attestation:
`--bind <sha256 of the result>` puts the result hash inside the signed digest of
an attestation for a fresh nonce, so the score belongs to *that* number and
cannot be transplanted onto another. A leaderboard stores
`(result, bind, score, reasons, cluster_id)` and shows "measured on real
hardware, score 0.97" next to each row. The reference integration for a tok/s
benchmark runner is in
[`docs/AFTERLIFE_INTEGRATION.md`](docs/AFTERLIFE_INTEGRATION.md)
(`afterlife bench --attest`).

```bash
R=$(sha256sum results.json | cut -d' ' -f1)
hwattest measure --server http://127.0.0.1:8787 --rp my-leaderboard --bind "$R"
```

**Bounty programs / sybil checks.** Contributors run `hwattest measure --server
URL --rp <program> --account <handle>`; the program reads back scores, reasons
and `cluster_id` from the submit response (or `GET /v1/clusters` with the admin
token) to see when many accounts resolve to one physical machine.

HTTP API: `POST /v1/challenge {rp_id, profile}`, `POST /v1/submit {payload,
account}`, `GET /v1/clusters?rp_id=` (Bearer admin token), `GET /v1/health`.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e . ruff mypy pytest
.venv/bin/pytest && .venv/bin/ruff check src tests eval && .venv/bin/mypy
```

## License and attribution

Apache-2.0 (see `LICENSE`, `NOTICE`). Copyright 2024-2026 Scott Boudreaux /
Elyan Labs. Measurement ideas and parts of the code are ported and reworked
from Elyan Labs' earlier Apache-2.0 hardware-fingerprint modules.

## Citation

If you use hwattest or its dataset, cite via [`CITATION.cff`](CITATION.cff) (a
DOI release is planned on Zenodo). The dataset is documented in
[`eval/DATASHEET.md`](eval/DATASHEET.md).

## Project layout

```
src/hwattest/
  workloads.py   seed-derived kernels shared by client and verifier
  plan.py        randomized measurement plans (profiles: standard/quick/tiny)
  challenge.py   HMAC-authenticated challenges, nonce store
  attest.py      run a plan -> submittable payload
  privacy.py     payload builder, salted per-RP IDs, inspect/describe
  measure/       clock, cache, jitter, simd, vmind, tpm (+ _ctx)
  score/         features, verify (anti-replay), scorer, pipeline
  cluster/       fingerprint + similarity + clustering
  server/        stdlib HTTP app + SQLite store
  cli.py         measure | inspect | serve | score
tests/           measurement, replay, scoring, clustering, server/CLI
eval/            collect, evaluate, replay, run_local.sh, vm/, FLEET_PLAN.md
```

There is no RustChain, token, or blockchain dependency anywhere in the library.

# Zenodo dataset-paper outline — DO NOT PUBLISH (for Scott)

A short dataset/software paper to accompany the Zenodo deposit and earn a
citable DOI. Target: a 4–6 page data descriptor (Zenodo "publication:
datapaper", or arXiv cs.CR + a Zenodo dataset record cross-linked). Draft only.
No token, no RTC. Every reported number must come from `eval/results/` with its
reproduce command; do not add a number the harness can't regenerate.

## Working title
"hwattest-eval: a labeled dataset and reproducible harness for probabilistic
hardware-authenticity scoring from software-only timing"

## Authors
Scott Boudreaux (Elyan Labs). ORCID: _[Scott to add]_.

## Abstract (≈150 words)
Self-reported machine signals and benchmark results can be produced by VMs,
emulators, or replayed traces, and existing anti-VM tools give defeatable
yes/no verdicts. We release hwattest-eval: a labeled dataset of software-only
hardware measurements (clock, cache-latency, instruction jitter, SIMD
throughput, VM indicators), each collected under a randomized server challenge,
together with the open harness that scores and clusters them. We report, on an
initial single-host release, the separation between bare-metal/container and
VM/emulator runs (ROC/AUC), false-positive rate on real hardware, a confusion
matrix, same-machine fingerprint repeatability, and the outcome of replay/forgery
attacks — including one rank-relabel-plus-noise forgery that defeats the current
verification. The dataset carries derived features and per-sample timings only,
with no machine identifiers, enforced by an included scanner. All numbers are
reproducible from the released artifacts.

## 1. Introduction / motivation
- Self-reported results problem: fake stars, indistinguishable benchmark fakes,
  sybil/bot farms; vendor attestation locked behind platform walls; WEI
  abandoned. (Cite StarScout/ICSE 2026, Play Integrity, Apple PATs, WEI.)
- Contribution: an *open, probabilistic, reasons-first* score; a labeled dataset
  + harness so claims are reproducible and the failure modes are public.

## 2. Methods
- 2.1 Challenge–response measurement protocol (randomized plan, nonce binding,
  per-sample `(index, params, start_ns, duration_ns, result)`, result
  re-execution).
- 2.2 Measurement modules (clock, cache, jitter, simd, vmind, optional tpm).
- 2.3 Feature extraction, transparent noisy-OR scoring, reasons.
- 2.4 Fingerprint + per-relying-party clustering.
- 2.5 Privacy design: derived features only, salted per-RP IDs, local-only mode;
  dataset built with `--no-id`; identifier scanner as a release gate.

## 3. Dataset (hwattest-eval/1)
- Composition table (41 records; 8 groups; counts) — from `eval/DATASHEET.md`.
- Collection: one host, controlled environments (bare/docker/KVM/hidden-KVM/
  TCG/hardened-TCG), `standard` profile.
- Format/schema; what is and is not present; the datasheet (Gebru et al. 2021).

## 4. Results (all from eval/results/, with reproduce commands)
- 4.1 Classification: AUC real_hardware/vm/emulator = 1.00; FPR on real hardware
  @0.5 = 0.0 (0/25); fakes accepted @0.5 = 0.0 (0/16); ROC table; confusion
  matrix (every group correct). `python3 eval/evaluate.py ...`
- 4.2 Same-machine repeatability: idle–idle median similarity 0.766
  (0.41–0.89, n=45), 97.8% ≥ 0.5 threshold; real-vs-emulator median ~0.08;
  load sensitivity (idle–load16 median 0.38).
- 4.3 Replay/forgery: resubmit/swap/relabel-index/relabel-rank all rejected
  10/10 with named reasons; **rank-relabel + 12% noise accepted 10/10** (the
  open bypass), forgery-to-source similarity 0.20–0.51. `python3 eval/replay.py`
- Figures: ROC curve; similarity-distribution box/violin per group pair;
  confusion heatmap. (Generate from the JSON; no new deps beyond matplotlib for
  the paper figures — not required to reproduce the numbers.)

## 5. Limitations / threats to validity (prominent, not buried)
- One machine; tiny per-class counts; provisional thresholds.
- VM/emulator guests expose device tells; a fully-scrubbed KVM VM is expected to
  pass; software-only measurement is defeatable by a patched client.
- The rank-relabel-plus-noise bypass is unresolved in v0.1.
- Fingerprints are quasi-identifying; two colluding relying parties could try to
  link feature vectors.

## 6. Reuse / fleet roadmap
- `eval/FLEET_PLAN.md`: multi-architecture, multi-machine collection (read-only,
  bounded) to answer cross-machine separation and vintage-CPU false positives.
- How others can contribute measurements and attacks.

## 7. Data & code availability
Software + dataset Apache-2.0; DOI via Zenodo (this deposit); `CITATION.cff`.

## References (to fill)
StarScout fake-stars (ICSE 2026); Gebru et al., Datasheets for Datasets (2021);
pafish/al-khaser; Play Integrity; Apple Private Access Tokens; Web Environment
Integrity (deprecated).

# Datasheet — hwattest-eval/1 (local release)

Following *Datasheets for Datasets* (Gebru et al., 2021). This describes the
dataset in `eval/data/local/` as released with hwattest v0.1.

## Motivation
Self-reported machine signals (and self-reported benchmark numbers) can be
produced by a VM, an emulator, or a replayed trace. This dataset exists so that
anyone can check our central claim for themselves: that software-only timing +
device features separate real bare-metal runs from VM/emulator/replay runs, and
can tell when two submissions came from the same physical machine. It is the
evidence behind the README's accuracy numbers. Created by Elyan Labs (Scott
Boudreaux) for the hwattest project; no external funding.

## Composition
- **Instances.** 41 labeled `hwattest measure` submissions (one JSON object per
  line, schema `hwattest-eval/1`). Each instance is one measurement run.
- **Fields.** `label` (`bare_metal`/`vm`/`emulator`/`container`), `sublabel`
  (`idle`/`load8`/`load16`/`docker`/`kvm`/`kvm_hidden`/`tcg`/`tcg_hardened`),
  `host_alias` (`host-1` — a neutral id; see *Confidentiality*), `condition`,
  `load_procs`, `loadavg_1m`, `run`, `collected_at` (UTC), and `payload`.
- **`payload`.** Exactly what the client sends by default: the challenge echo,
  per-challenge-sample `(index, parameters, start_ns, duration_ns, result)`
  timings, derived features (VM-indicator *categories*, SIMD-relevant CPU flags,
  generic CPU vendor, arch, logical CPU count, clocksource name, rounded ppm),
  and a self-issued challenge so the record verifies offline
  (`allow_self=True`). Built with `--no-id`, so **no salted machine ID** is
  present either.
- **Labels.** The ground truth is the execution environment, which we controlled
  when collecting (bare metal vs a docker container vs a KVM guest vs QEMU TCG).
- **Class counts.** bare_metal/idle 10, bare_metal/load8 5, bare_metal/load16 5,
  container/docker 5, vm/kvm 5, vm/kvm_hidden 5, emulator/tcg 3,
  emulator/tcg_hardened 3.
- **Splits.** None; the set is small enough to report on in full. For honest
  accuracy you need *different physical machines*, which this release does not
  have (see *Limitations*).

## Collection
- One physical host: an HP Victus laptop (AMD Ryzen 7 8845HS, 16 threads,
  Linux 6.17), December-2026 lab environment.
- `eval/run_local.sh` drives `eval/collect.py` for the bare-metal and container
  rows; `eval/vm/run_guest.sh` boots throwaway QEMU guests (KVM `-cpu host`;
  `kvm_hidden` with the CPUID hypervisor bit cleared and SMBIOS spoofed to Dell;
  TCG full-system; `tcg_hardened` with device tells also scrubbed) and runs the
  client inside them.
- Each run uses the `standard` profile; ~3 s on bare metal, ~35 s under TCG.

## Preprocessing / cleaning
None on the measurements. The only post-hoc edit is the `host_alias` field,
set to the neutral value `host-1` because all 41 records come from the one
physical machine (the execution context is already in `label`/`sublabel`).
`eval/verify_no_identifiers.py` is run as a release gate and in CI
(`tests/test_dataset_privacy.py`).

## Uses
- **Appropriate:** reproducing the README's ROC/AUC, FPR-on-real-hardware,
  confusion matrix and same-machine similarity numbers; developing and
  regression-testing detectors; as a seed for a larger multi-machine release.
- **Not appropriate:** as a general accuracy benchmark (one CPU), for gating
  essential services, or for any claim about human identity or work quality.

## Distribution & license
Released with the hwattest source under **Apache-2.0**. Cite via `CITATION.cff`.
A DOI release is planned on Zenodo (see `drafts/ZENODO_DEPOSIT.md`).

## Confidentiality / privacy
No raw identifiers were ever collected into `payload`: no MAC addresses, no
`/etc/machine-id`, no serials, no hostnames, no CPU *model* string (only the
generic vendor `AuthenticAMD`), and — because of `--no-id` — no salted
per-relying-party machine ID. The random high-entropy fields that are present
(challenge nonce, payload digest, seed-derived kernel `result` samples) are
per-run values, not identifiers. The VM-token fields (e.g. `qemu`, `kvm-clock`)
identify the *hypervisor class*, which is the detection signal, not the host.
This is verified mechanically; see `eval/verify_no_identifiers.py`.

## Limitations (read these)
- **One machine.** Whether different machines of the same model separate, and
  whether genuinely slow vintage CPUs trip the emulator heuristics, is **not
  measured here**. Thresholds are provisional. `eval/FLEET_PLAN.md` is the plan
  to fix this.
- **Tiny per-class counts** (3–10). The AUC=1.00 numbers mean the signals
  separate cleanly *on this host*, not that the detector is perfect.
- **The VM/emulator guests expose device-level tells.** A VM that scrubs every
  device tell and runs under hardware virtualization is expected to score as
  real hardware (documented in the README and in `attacks/FOOLED_IT.md`).

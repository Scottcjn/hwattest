# Fleet measurement plan (NOT yet run; needs Scott's approval)

v0.1 numbers come from **one machine** (the Victus). The claims that matter
most (do *different* physical machines of the same model separate? do slow
real CPUs get mistaken for emulators?) can only be answered by measuring
other machines. This is the plan. Nothing below has been run.

## Rules for every host

- Read-only benchmark: copies a ~60 KB tarball into `~/hwa-eval/`, runs
  `eval/collect.py` (pure Python, single-threaded, ~3 s per run on a 2024
  laptop; scales with CPU speed, hard cap 60 s per module), copies one JSONL
  file back, then deletes `~/hwa-eval/`. No root, no installs, no services, no
  GPU use, nothing left running.
- Needs `python3 >= 3.9` on the host. Check first; if it is older or absent,
  **skip the host** (do not install anything) and note it.
- Never touch RustChain nodes <rustchain-node> / <rustchain-node>.
- Respect other users' jobs: check `uptime` first. If the host is busy, record
  it (the collector stores the 1-minute load average) rather than stopping
  anyone's work; label the run `--sublabel busy`.
- Credentials are not in this file; use your normal SSH setup.

## Per-host commands (run from the repo root on the Victus)

```bash
HOST=user@host            # see table
ALIAS=g6kf                # short lab nickname, goes into the dataset
tar -czf ../scratch/hwa.tgz src eval/collect.py
scp ../scratch/hwa.tgz "$HOST":hwa.tgz
ssh "$HOST" 'python3 --version && uptime && mkdir -p ~/hwa-eval && tar -C ~/hwa-eval -xzf ~/hwa.tgz && \
  python3 ~/hwa-eval/eval/collect.py --label bare_metal --sublabel idle --host-alias '"$ALIAS"' \
    --runs 5 --out ~/hwa-eval/out.jsonl'
# optional, only where it will not disturb anyone: same under load
ssh "$HOST" 'python3 ~/hwa-eval/eval/collect.py --label bare_metal --sublabel load \
    --host-alias '"$ALIAS"' --runs 3 --load 4 --out ~/hwa-eval/out.jsonl'
mkdir -p eval/data/fleet && scp "$HOST":hwa-eval/out.jsonl eval/data/fleet/"$ALIAS".jsonl
ssh "$HOST" 'rm -rf ~/hwa-eval ~/hwa.tgz'
```

Docker control where Docker exists and an image with python >= 3.9 is
already present locally on that host (no pulls):

```bash
ssh "$HOST" 'docker run --rm --network none -v ~/hwa-eval:/w python:3.12-slim \
  python3 /w/eval/collect.py --label container --sublabel docker --host-alias '"$ALIAS"'-docker \
  --runs 3 --out /w/out.jsonl'
```

Then evaluate everything together:

```bash
python3 eval/evaluate.py eval/data/local/*.jsonl eval/data/fleet/*.jsonl \
  --out eval/results/fleet_metrics.json
```

## Hosts (priority order) and why

| # | Host (alias) | Address | Why it matters | Notes / expected blockers |
|---|---|---|---|---|
| 1 | Gigabyte G6 KF (`g6kf`) | <lab-host> / TS <tailnet-host> | 2nd modern x86 laptop (Intel i7-13620H): first cross-machine separation test vs the Victus (AMD) | CPU-only run; leave `elya-llm.service` / V100 alone; label `busy` if the LLM is serving |
| 2 | Mac Mini M2 (`m2`) | <lab-host> | macOS + arm64 path (sysctl flags, no /proc, no DMI) | macOS system python may be 3.9 (Xcode CLT); skip if older |
| 3 | i7-8700K tower (`i7tower`) | <lab-host> | Intel desktop, older generation (2017) | |
| 4 | A51 R2 (`a51r2`) | <lab-host> | Intel HEDT (i7-5930K, 2014): old-but-fast x86 | |
| 5 | C4130 #1 (`c4130a`) | <lab-host> | Dual-socket-class Xeon server, big L3 | GPUs not touched |
| 6 | LTX server (`ltx136`) | <lab-host> | Another x86 box | may be rendering: check load, label `busy` |
| 7 | .150 / .191 (`h150`, `mi191`) | <lab-host> / .191 | More x86 diversity | .191 runs services (Strata/MI50): CPU-only run, label `busy` if loaded |
| 8 | IBM POWER8 S824 (`power8`) | TS <tailnet-host> | Big-endian-free but non-x86 (ppc64le), VSX/AltiVec SIMD path, huge caches | Ubuntu 20.04 ships **python 3.8**: expected to be skipped unless a >= 3.9 python already exists; llama-server (port 8082, 64 threads) usually busy -> label `busy` |
| 9 | Power Mac G5 (`g5`) / Dual G4 (`g4mdd`) / PowerBook G4s | .130 / .179 / .125 / .115 | Vintage slow CPUs: the key false-positive test for the emulator heuristics (a slow interpreter looks like emulation on some ratios) | Mac OS X 10.4/10.5 have python 2.x only -> **blocked** for v0.1 (would need a py2/py3.x-portable client; out of scope) |

Local, no extra approval needed (same Victus, already has the image):
QEMU **ppc64 TCG** guest from `~/hwfp-bench/tcg-lab/ppc64el.img`, an emulated
POWER machine to compare against the real POWER8 if #8 can run.

## What we will report from the fleet

- AUC / FPR recomputed with every host as a positive.
- Cross-machine similarity: every pair of *different* hosts, especially the
  two x86 laptops and any same-model pairs; this sets `same_machine`.
- Per-host: does any real host get `emulator >= 0.5` (vintage/slow-CPU false
  positives)? Which reasons fired?
- Sample sizes per host, idle vs busy.

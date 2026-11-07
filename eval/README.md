# Evaluation

`collect.py` captures labeled measurements; `evaluate.py` scores a dataset and
reports metrics; `replay.py` runs forgery/replay attacks; `run_local.sh`
collects the local (this-machine-only) dataset; `vm/run_guest.sh` boots a local
throwaway QEMU guest and measures inside it.

- Dataset format: JSONL, schema `hwattest-eval/1`, one measurement per line
  (see `collect.py` docstring). Payloads carry derived features + per-sample
  timings, **no raw identifiers and no machine IDs** (`collect.py` passes
  `--no-id`), so the dataset is publishable.
- Reproduce the local dataset: `PYTHON=../.venv/bin/python ./run_local.sh`
  then `python3 evaluate.py data/local/*.jsonl --out results/local_metrics.json`.
- `FLEET_PLAN.md`: the other lab machines to measure, exact read-only commands,
  and expected blockers. **Not yet run** - needs Scott's approval.

Results committed in `results/` were produced on the HP Victus only. See the
top-level README "Evaluation" section for numbers, sample sizes and caveats.

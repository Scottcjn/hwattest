# hwattest launch-prep — REPORT (launch-hwattest agent, 2026-11-06)

Made the existing `hwattest` v0.1 package launch-ready without weakening the
honest-limits or the open-bypass disclosure, and without publishing anything.
NO push, NO repo creation, NO Zenodo deposit — all queued for Scott.

## What I built (5 commits on `main`, local only)

**1. Evaluation as the headline + publishable dataset.**
- `eval/verify_no_identifiers.py` — fail-closed identifier scanner (importable +
  CLI): rejects MACs, serial/uuid/hostname/machine_id keys, CPU *model* strings,
  and unexplained long hex, allowlisting the legitimately random nonce/digest/
  kernel-result fields. Prints `CLEAN: 41 record(s) ...`.
- Neutralized `host_alias` ("victus"/"-docker"/"-guest") → `host-1` across all
  41 records (one physical host; context is already in label/sublabel).
  `eval/results/local_metrics.json` byte-identical after the edit.
- `tests/test_dataset_privacy.py` (7 tests): dataset is clean AND the scanner
  catches planted MAC / model-string / serial-key identifiers.
- `eval/DATASHEET.md` — Datasheets-for-Datasets record.
- `eval/attacks/FOOLED_IT.md` — public "how we fooled it" log, seeded with the
  open bypass (#5 rank-relabel + ~12% noise) and honest status of all 10
  attacks. Referenced test names / CLI flags verified to exist.

**2. README reposition.** Opens "Is this benchmark result real? One command,
~90 seconds ... with reasons." Benchmark `--bind` is the lead use; bounty
anti-sybil secondary. Eval section has the full reproduce block + DATASHEET /
FOOLED_IT links; intro states both AUC=1.00 and the open bypass. No token/RTC.

**3. Afterlife trust-layer.** `docs/AFTERLIFE_INTEGRATION.md` specs
`afterlife bench --attest` (R=sha256(row) → challenge → measure --bind R →
score+nonce+bind+cluster_id per row). Coordination-only; afterlife repo
untouched. `CITATION.cff` added (software + dataset).

**4. Launch drafts (`drafts/`, DO-NOT-POST):** show_hn.md, devto_localllama.md,
zenodo_dataset_paper.md, ZENODO_DEPOSIT.md. Eval-first, no token, numbers trace
to eval/results/.

## Verification
- pytest: **53 passed** (+7). ruff(src tests eval): **clean**. mypy strict:
  **no issues, 26 files**. Scanner: **CLEAN, 41 records, 0 identifiers**.
- Dev tooling in `.venv-dev/` (gitignored); shipped `.venv/` lacks pytest.

## Queue (needs_scott=true) in growth-week1/QUEUE.jsonl
hwattest-create-repo → hwattest-push → hwattest-release (v0.1.0) →
hwattest-zenodo (manual UI). Exact commands; none run.

## Could NOT verify / left for Scott
- Full CFF schema validation (only PyYAML parse done — valid YAML).
- `drafts/release_notes_v0.1.0.md` not written (needs final tag decision).
- DOI blank in CITATION.cff until Zenodo mints it.
- Still one host; no fleet data (eval/FLEET_PLAN.md unchanged).

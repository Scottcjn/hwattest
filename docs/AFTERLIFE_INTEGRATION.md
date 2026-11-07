# hwattest as the trust layer for Afterlife `bench`

**Status: proposal / coordination doc.** This lives in the hwattest repo. It
describes an integration for the separate *Afterlife* project (a pinned stack +
benchmark runner for stranded datacenter GPUs) **without changing the Afterlife
repo**. The Afterlife SPEC already reserves the hook: *"Optionally attach an
hw-attest score to every row."* This spells out exactly how, so whoever wires it
up — on the Afterlife side — has a fixed contract to build against. Nothing here
is wired in yet; do not describe it as shipped.

## The problem it solves for Afterlife

Afterlife's headline is a tok/s number on an old GPU (e.g. "Gemma 4 26B at
~107 tok/s on a 2017 V100"). The first thing a skeptical reader on HN or
r/LocalLLaMA says is *"a number in a README proves nothing — was that a real
card, or a cloud VM, or a cherry-picked run you can't reproduce?"* Afterlife
already answers the reproducibility half (every cell carries a reproduce
command). hwattest answers the other half: **was the row measured on a real,
distinct physical machine?** — as a score with reasons, bound to that specific
result so it cannot be transplanted onto a different number.

It does **not** prove the tok/s is correct, and it is not a substitute for the
correctness gate (perplexity vs the RTX 3060 reference + the fixed answer set).
It is one more column that says "this came from real silicon," with an honest
confidence and a reasons list. Keep the SPEC's rule: a cell with no reproduce
command stays out of the README — the attestation does not replace that.

## Contract: `afterlife bench --attest`

When `--attest` is passed, the bench runner, **after** a row's measurement and
correctness gate pass:

1. Serialize the result row canonically (sorted keys, UTF-8, no insignificant
   whitespace) and compute `R = sha256(canonical_row)`.
2. Request a fresh challenge from the configured hwattest server:
   `POST {attest_server}/v1/challenge {"rp_id": "afterlife-bench", "profile": "standard"}`.
3. Run the hwattest client **on the machine under test** bound to the result:
   `hwattest measure --server {attest_server} --rp afterlife-bench --bind "$R"`
   (equivalently call `hwattest.attest.attest(challenge, bind=R)` in-process and
   `POST /v1/submit`). The `standard` profile is ~3 s on a modern box; it must
   run on the same host that produced the tok/s number, not a controller.
4. Store the fields below on the row and move on. The bench must **degrade
   gracefully**: if the attest server is unreachable or the submit is rejected,
   write `attest.status` accordingly and still emit the row — attestation is
   additive, never a gate on publishing a reproduce-backed number.

### Fields added to each JSON/CSV row

| Field | From | Meaning |
|---|---|---|
| `attest.score_real_hardware` | submit `result.scores.real_hardware` | 0–1 authenticity score |
| `attest.score_vm` / `attest.score_emulator` | `result.scores.*` | contributing dimensions |
| `attest.integrity` | `result.scores.integrity` | 0 if verification rejected; 0.3 if summary-only |
| `attest.bind` | echoed `bind` | must equal `R`; proves the score is tied to this row |
| `attest.cluster_id` | submit `cluster_id` | same physical machine across rows/accounts |
| `attest.reasons` | `result.reasons` (top N) | human-readable why |
| `attest.nonce` | the challenge nonce | ties the run to a server-issued, single-use challenge and time window |
| `attest.rp_id` | `"afterlife-bench"` | the relying party |
| `attest.server` | config | which hwattest instance scored it |
| `attest.status` | `ok` / `unreachable` / `rejected:<reason>` | fail-open marker |

### README rendering

A row renders as, e.g., `107 tok/s · attested 0.97 (real hardware)`. Below the
cliff matrix, link this doc and state the honest caveats verbatim from the
hwattest README's *Honest limits* — do not soften them. In particular: a VM that
scrubs every device tell and runs under hardware virtualization is expected to
score as real hardware, and the rank-relabel-plus-noise forgery passes v0.1
verification (see `eval/attacks/FOOLED_IT.md`). The right framing is "this row
was measured on what looks like real silicon, score X, here's why," not "this
row is proven genuine."

## Verification notes (for whoever implements it)

- `bind` is covered by the attestation's `digest`, which is in turn bound to the
  server's single-use `nonce`; a score for one `R` cannot be reused for another
  result without a fresh challenge and a fresh measurement. Verify
  `attest.bind == R` on ingest and reject the row's attestation if not.
- Keep the relying-party id stable (`afterlife-bench`) so clustering can see one
  physical machine submitting many rows; that is a feature (a submitter benching
  five cards on one host should cluster), not a problem.
- Privacy: the default payload carries no raw identifiers; the per-RP
  `machine_id_rp` is derived and non-joinable across relying parties. If the
  public leaderboard stores `cluster_id`, note it in the Afterlife privacy
  section — it is linkable *within* `afterlife-bench`.
- Run the hwattest server yourself (it binds `127.0.0.1`; put TLS in front).
  Do not point Afterlife at a third-party scorer you do not control.

## What this is NOT

- Not a correctness check (that is Afterlife's perplexity + answer-set gate).
- Not a proof, not a gate, not anti-fraud insurance. A determined faker with a
  patched client can still post a number; this raises the cost and makes the
  claim legible. Say so wherever the column appears.

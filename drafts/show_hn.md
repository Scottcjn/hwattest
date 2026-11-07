# Show HN draft — DO NOT POST (for Scott to review/submit)

Launch rule: nothing here is published. This is a draft for Scott to post
manually. No token, no coin, eval-first. Every number below traces to
`eval/results/` — do not add a number without a reproduce command.

---

**Title (<80 chars, pick one):**
- `Show HN: hwattest – is a benchmark result from a real machine, or a VM? (score+reasons)`
- `Show HN: Probabilistic hardware-authenticity scoring, with the attack that beats it`

**URL:** https://github.com/Scottcjn/hwattest

---

**Post body:**

A tok/s number or a Geekbench score you read online is self-reported. Nothing
stops someone posting a fast result that actually came from a cloud VM, a
binary-translation emulator, or a recording of someone else's machine. hwattest
attaches a *probabilistic* hardware-authenticity score — with human-readable
reasons — to a submission: how likely it was produced on a real, distinct
physical machine, bound to that specific result so the score can't be moved onto
a different number.

It's a client that measures (clock/oscillator cost, cache-latency curve,
instruction jitter, SIMD throughput, VM/hypervisor indicators, optional TPM
quote) under a server-issued challenge, and a self-hostable server that scores
and clusters. Output is a score per dimension (real-hardware / vm / emulator /
same-machine) with reasons, **never a yes/no proof**. Python 3.9+, standard
library only. Apache-2.0. No token, no blockchain — it's extracted from a
hardware-fingerprint system that used to be tied to one, with the token dropped.

I'm leading with the evaluation because that's the only thing that should
convince you, and with the attack that beats it because you'd find it anyway:

- On one machine (an AMD Ryzen 7 laptop), bare-metal/container vs VM/emulator
  separate cleanly: AUC 1.00, 0/25 real runs wrongly rejected at threshold 0.5,
  0/16 fakes accepted, including a KVM guest with the CPUID hypervisor bit
  cleared and SMBIOS spoofed (caught by leftover device tells, not timing).
- **The hole:** an attacker who re-executes every challenge kernel honestly but
  sources the *timings* from a recording of a real machine — mapped by rank onto
  the new parameters and perturbed ~12% — **passes v0.1 verification.**
  Clustering doesn't reliably catch it either (forgery-to-source similarity
  0.20–0.51, mostly below the same-machine threshold). It's logged as a failing
  … well, a *passing* test, in `eval/attacks/FOOLED_IT.md`.

Honest limits, up front: software-only measurement runs on the machine being
judged, so a fully patched client can fabricate everything; this detects machine
*realness and distinctness*, not human intent or work quality; it's for opt-in,
low-stakes uses (benchmark leaderboards, bounty anti-sybil, research datasets),
not for gating anything essential; and the evaluation so far is **one machine** —
whether different machines of the same model separate is not measured yet.

The labeled dataset (derived features only, no machine identifiers — there's a
scanner + CI test that enforces it) and the full harness are in the repo, so you
can reproduce every number and try to beat it. If you get a fake past it, send a
recipe and it goes in the attack log with credit.

Reference integration: attaching a score to an open-GPU benchmark runner
(`docs/AFTERLIFE_INTEGRATION.md`).

---

**Pre-submit checklist for Scott:**
- [ ] Repo is public and the eval numbers in the post still match `eval/results/`.
- [ ] `eval/attacks/FOOLED_IT.md` link resolves.
- [ ] Post from your own account; be around for the first few hours to answer.
- [ ] Expected first question: "one machine?" — the answer is yes, and the
      FLEET_PLAN is how it gets fixed. Don't overclaim.

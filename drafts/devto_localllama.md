# dev.to / r/LocalLLaMA draft — DO NOT POST (for Scott to review/submit)

Launch rule: draft only, posted manually by Scott. No token. Numbers trace to
`eval/results/`. r/LocalLLaMA is allergic to hype and to anything that smells
like a coin — lead with the problem and the limits, not the pitch.

---

**Title:** You can't trust a self-reported tok/s. Here's a tool that scores how
likely a benchmark ran on real hardware (and the attack that beats it).

---

Every week someone posts "X tok/s on $CHEAP_GPU" and the thread spends 40
comments trying to figure out if it's real: Was it a quant nobody else uses? Was
it a VM on a borrowed H100? Was it even run at all, or copied from another
thread? The number is self-reported, and there's no cheap way to check the
*hardware* half of that question.

I built a small open tool for exactly that half. **hwattest** measures a machine
(clock/oscillator cost, cache-latency curve, instruction jitter, SIMD
throughput, VM/hypervisor indicators, optional TPM quote) under a
server-issued challenge and returns a *probabilistic* score with reasons: how
likely this ran on a real, distinct physical machine vs a VM, an emulator, or a
replayed trace. You can bind it to a specific result hash, so "measured on real
hardware, score 0.97" sticks to *that* tok/s number and can't be transplanted.

What it is **not**: a correctness check (it doesn't tell you the tok/s is right —
run your own perplexity gate for that), and not a proof. It's a confidence score
with the reasons shown.

**The eval, because that's the only part that matters.** On one machine (a Ryzen
7 laptop), real (bare metal + docker) vs fake (KVM, hidden KVM, QEMU TCG)
separated with AUC 1.00, zero real runs wrongly rejected, zero fakes accepted —
including a KVM guest with the hypervisor CPUID bit cleared and SMBIOS spoofed
(caught by leftover virtio/clocksource/steal-time tells, not by timing).

**The attack that works.** If you re-run every challenge kernel for its real
result but feed it *timings* copied from a recording of a real machine —
rank-mapped onto the new parameters and jittered ~12% — it passes v0.1
verification. Clustering doesn't reliably catch it (forgery-vs-source similarity
0.20–0.51). It's in the repo as a passing test and in a public "how we fooled
it" log. Software-only measurement runs on the machine being judged, so a fully
patched client can fabricate anything — this raises the cost, it doesn't close
the door.

The honest caveat for this crowd: the eval is **one machine** so far. Whether two
different 3090s separate, and whether a genuinely slow old CPU trips the
emulator heuristics, isn't measured yet. The dataset (derived features only, no
identifiers) and harness are in the repo so you can reproduce it and, ideally,
break it.

Apache-2.0, Python stdlib only, no account, no token, self-hostable. Repo:
https://github.com/Scottcjn/hwattest

If you land a new bypass, send a reproduce recipe — it goes in the attack log
with credit. That's the whole point.

---

**Notes for Scott:**
- r/LocalLLaMA: post as text, not a link post; no emoji-spam; answer the "one
  machine" question in the first reply before someone else raises it.
- dev.to: add tags `opensource`, `security`, `machinelearning`, `python`.
- Do NOT cross-link RTC/RustChain anywhere in or around this post.

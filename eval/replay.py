#!/usr/bin/env python3
"""Replay / forgery attacks against a live in-process issuer.

For each trial: run one genuine measurement for a fresh challenge (A), submit
it, then try to get credit for new challenges using A's recording:

* ``genuine``        fresh run for A (should be accepted: false-reject rate)
* ``resubmit``       A's payload submitted again
* ``swap_challenge`` A's samples under challenge B (digest recomputed)
* ``relabel_index``  A's timings re-labelled onto B's plan, every kernel
                     re-executed for its result (strong attacker)
* ``relabel_rank``   as above, timings assigned by rank of the new parameters
* ``relabel_rank_noise`` rank re-label + 12% multiplicative noise (models our
                     checks; a known open bypass)

    python3 eval/replay.py --trials 10 --out eval/results/replay.json
"""

import argparse
import copy
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, os.path.join(HERE, ".."))

from hwattest.attest import attest, payload_digest  # noqa: E402
from hwattest.challenge import Issuer  # noqa: E402
from hwattest.cluster.cluster import fingerprint, similarity  # noqa: E402
from hwattest.score.features import extract  # noqa: E402
from hwattest.score.verify import verify  # noqa: E402
from tests.forge import relabel  # noqa: E402

ATTACKS = ["genuine", "resubmit", "swap_challenge", "relabel_index", "relabel_rank",
           "relabel_rank_noise"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--profile", default="standard")
    ap.add_argument("--out")
    a = ap.parse_args()

    iss = Issuer(profile=a.profile)
    outcome = {k: Counter() for k in ATTACKS}
    reasons = {k: Counter() for k in ATTACKS}
    sim_to_source = []

    def sub(kind, p):
        v = verify(p, iss.authentic, iss.store, time.time())
        outcome[kind]["accepted" if v["accepted"] else "rejected"] += 1
        for r in v["rejections"]:
            reasons[kind][r] += 1
        return v

    for trial in range(a.trials):
        pa, _ = attest(iss.issue("eval"), no_id=True)
        sub("genuine", pa)
        sub("resubmit", copy.deepcopy(pa))
        sw = copy.deepcopy(pa)
        sw["challenge"] = iss.issue("eval")
        sw["digest"] = payload_digest(sw)
        sub("swap_challenge", sw)
        sub("relabel_index", relabel(pa, iss.issue("eval"), mode="index"))
        sub("relabel_rank", relabel(pa, iss.issue("eval"), mode="rank"))
        fz = relabel(pa, iss.issue("eval"), mode="rank", noise=0.12, seed=trial)
        v = sub("relabel_rank_noise", fz)
        if v["accepted"]:
            s, _ = similarity(fingerprint(extract(pa)), fingerprint(extract(fz)))
            sim_to_source.append(round(s, 3))
        print(f"trial {trial}: " + ", ".join(
            f"{k}={dict(outcome[k])}" for k in ATTACKS), file=sys.stderr)

    out = {
        "trials": a.trials,
        "profile": a.profile,
        "outcome": {k: dict(v) for k, v in outcome.items()},
        "rejection_reasons": {k: dict(v) for k, v in reasons.items()},
        "accepted_forgery_similarity_to_source": sim_to_source,
    }
    txt = json.dumps(out, indent=1)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w") as f:
            f.write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()

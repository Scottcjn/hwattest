#!/usr/bin/env python3
"""Score a labeled dataset and report metrics. Measure, don't claim.

    python3 eval/evaluate.py eval/data/local/*.jsonl --out eval/results/local_metrics.json

Metrics (every number is reported with its sample size):
* ROC/AUC of ``real_hardware`` (positives: bare_metal + container, which runs on
  bare metal; negatives: vm + emulator), AUC of ``vm`` and ``emulator``.
* FPR on real hardware: fraction of real-hardware runs scored < threshold
  (wrongly called not-real), at threshold 0.5.
* Confusion matrix of the argmax rule (emulator >= .5 -> emulator, elif vm >= .5
  -> vm, elif container >= .5 -> container, else bare_metal) by true sublabel.
* Same-machine repeatability: fingerprint similarity distributions between
  groups, and the fraction of pairs above the clustering threshold.
"""

import argparse
import itertools
import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from hwattest._stats import median, quantile  # noqa: E402
from hwattest.challenge import MemoryStore  # noqa: E402
from hwattest.cluster.cluster import DEFAULT_SAME_MACHINE, fingerprint, similarity  # noqa: E402
from hwattest.score.pipeline import evaluate  # noqa: E402

REAL = {"bare_metal", "container"}


def auc(pos, neg):
    """Mann-Whitney AUC; ties count one half."""
    if not pos or not neg:
        return None
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def roc(pos, neg):
    pts = []
    for t in sorted(set(pos + neg + [1.01]), reverse=True):
        tpr = sum(1 for p in pos if p >= t) / len(pos)
        fpr = sum(1 for n in neg if n >= t) / len(neg)
        pts.append([round(t, 3), round(fpr, 3), round(tpr, 3)])
    return pts


def predict(scores):
    if scores["emulator"] >= 0.5:
        return "emulator"
    if scores["vm"] >= 0.5:
        return "vm"
    if scores["container"] >= 0.5:
        return "container"
    return "bare_metal"


def dist(xs):
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "min": round(min(xs), 3), "p10": round(quantile(xs, 0.1), 3),
            "median": round(median(xs), 3), "max": round(max(xs), 3)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--out")
    ap.add_argument("--threshold", type=float, default=0.5)
    a = ap.parse_args()

    rows = []
    for path in a.files:
        with open(path) as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
    store = MemoryStore()
    for r in rows:
        ev = evaluate(r["payload"], lambda ch: False, store, allow_self=True, offline=True)
        r["_res"] = ev["result"]
        r["_fp"] = fingerprint(ev["features"])
        r["_group"] = f"{r['label']}/{r.get('sublabel') or '-'}"

    per_group = defaultdict(list)
    for r in rows:
        per_group[r["_group"]].append(r)

    rh_pos = [r["_res"]["scores"]["real_hardware"] for r in rows if r["label"] in REAL]
    rh_neg = [r["_res"]["scores"]["real_hardware"] for r in rows if r["label"] not in REAL]
    vm_pos = [r["_res"]["scores"]["vm"] for r in rows if r["label"] == "vm"]
    vm_neg = [r["_res"]["scores"]["vm"] for r in rows if r["label"] in REAL]
    em_pos = [r["_res"]["scores"]["emulator"] for r in rows if r["label"] == "emulator"]
    em_neg = [r["_res"]["scores"]["emulator"] for r in rows if r["label"] != "emulator"]

    t = a.threshold
    fpr_real = (sum(1 for s in rh_pos if s < t) / len(rh_pos)) if rh_pos else None
    accept_fake = (sum(1 for s in rh_neg if s >= t) / len(rh_neg)) if rh_neg else None

    confusion = {g: dict(Counter(predict(r["_res"]["scores"]) for r in rs))
                 for g, rs in sorted(per_group.items())}

    group_scores = {
        g: {k: dist([r["_res"]["scores"][k] for r in rs])
            for k in ("real_hardware", "vm", "emulator", "container", "integrity")}
        for g, rs in sorted(per_group.items())
    }
    top_reasons = {
        g: Counter(x["feature"] for r in rs for x in r["_res"]["reasons"]
                   if x["weight"] > 0).most_common(8)
        for g, rs in sorted(per_group.items())
    }
    rejections = {g: Counter(c for r in rs for c in r["_res"]["verification"]["rejections"])
                  for g, rs in sorted(per_group.items())}

    # Same-machine repeatability (every group here ran on the same physical host).
    sims = {}
    names = sorted(per_group)
    for g1, g2 in itertools.combinations_with_replacement(names, 2):
        if g1 == g2:
            pairs = itertools.combinations(per_group[g1], 2)
        else:
            pairs = itertools.product(per_group[g1], per_group[g2])
        vals = [similarity(x["_fp"], y["_fp"])[0] for x, y in pairs]
        if vals:
            d = dist(vals)
            d["frac_ge_threshold"] = round(sum(v >= DEFAULT_SAME_MACHINE for v in vals)
                                           / len(vals), 3)
            sims[f"{g1} ~ {g2}"] = d

    out = {
        "n_records": len(rows),
        "n_by_group": {g: len(rs) for g, rs in sorted(per_group.items())},
        "threshold": t,
        "auc_real_hardware": auc(rh_pos, rh_neg),
        "auc_vm": auc(vm_pos, vm_neg),
        "auc_emulator": auc(em_pos, em_neg),
        "n_pos_real": len(rh_pos), "n_neg_real": len(rh_neg),
        "fpr_on_real_hardware": fpr_real,
        "fake_accepted_as_real": accept_fake,
        "roc_real_hardware": roc(rh_pos, rh_neg) if rh_pos and rh_neg else None,
        "confusion_by_sublabel": confusion,
        "scores_by_group": group_scores,
        "top_reasons_by_group": top_reasons,
        "verification_rejections_by_group": {g: dict(c) for g, c in rejections.items()},
        "same_machine_threshold": DEFAULT_SAME_MACHINE,
        "similarity": sims,
    }
    txt = json.dumps(out, indent=1)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w") as f:
            f.write(txt + "\n")
    # Short human summary.
    print(f"records: {len(rows)}  groups: {out['n_by_group']}")
    print(f"AUC real_hardware={out['auc_real_hardware']}  (pos n={len(rh_pos)}, "
          f"neg n={len(rh_neg)})  AUC vm={out['auc_vm']}  AUC emulator={out['auc_emulator']}")
    print(f"FPR on real hardware @{t}: {fpr_real}   fakes accepted as real @{t}: {accept_fake}")
    print("confusion (true sublabel -> predicted):")
    for g, c in confusion.items():
        print(f"  {g:28s} {c}")
    print("similarity (median [min..max], frac >= threshold):")
    for k, d in sims.items():
        print(f"  {k:52s} n={d['n']:4d} med={d['median']} [{d['min']}..{d['max']}]"
              f" ge={d['frac_ge_threshold']}")


if __name__ == "__main__":
    main()

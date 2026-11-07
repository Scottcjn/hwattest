#!/usr/bin/env python3
"""Collect labeled hwattest measurements into a JSONL dataset.

Each line (schema ``hwattest-eval/1``)::

    {"schema": "hwattest-eval/1", "label": "bare_metal|vm|emulator|container",
     "sublabel": "e.g. kvm, kvm_hidden, tcg, tcg_hardened, docker",
     "host_alias": "lab nickname", "condition": "idle|load", "run": 0,
     "collected_at": "UTC ISO-8601", "load_procs": 0, "payload": {...}}

``payload`` is exactly what ``hwattest measure`` would send by default
(no raw identifiers, no salted machine IDs; a self-issued challenge, so the
dataset can be verified offline with ``allow_self=True``).

Run from a checkout (no install needed)::

    python3 eval/collect.py --label bare_metal --host-alias victus --runs 5 \
        --out eval/data/victus.jsonl [--load 8]
"""

import argparse
import datetime
import json
import multiprocessing
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from hwattest.attest import attest  # noqa: E402
from hwattest.challenge import self_challenge  # noqa: E402


def _burn(stop_evt):  # CPU load generator (pure Python spin)
    x = 1
    while not stop_evt.is_set():
        for _ in range(100000):
            x = (x * 1103515245 + 12345) & 0x7FFFFFFF


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True,
                    choices=["bare_metal", "vm", "emulator", "container"])
    ap.add_argument("--sublabel", default="")
    ap.add_argument("--host-alias", required=True)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--profile", default="standard")
    ap.add_argument("--load", type=int, default=0, help="number of busy-loop processes")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    stop = multiprocessing.Event()
    procs = [multiprocessing.Process(target=_burn, args=(stop,), daemon=True)
             for _ in range(a.load)]
    for p in procs:
        p.start()
    try:
        with open(a.out, "a") as f:
            for i in range(a.runs):
                ch = self_challenge("eval", a.profile)
                payload, _ = attest(ch, no_id=True)  # dataset: no machine IDs
                rec = {
                    "schema": "hwattest-eval/1",
                    "label": a.label,
                    "sublabel": a.sublabel,
                    "host_alias": a.host_alias,
                    "condition": "load" if a.load else "idle",
                    "load_procs": a.load,
                    "run": i,
                    "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "payload": payload,
                }
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                f.flush()
                el = payload["session"]["elapsed_ns"] / 1e9
                print(f"[{a.host_alias}/{a.sublabel or a.label}] run {i} done in {el:.1f}s",
                      file=sys.stderr)
    finally:
        stop.set()
        for p in procs:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()


if __name__ == "__main__":
    main()

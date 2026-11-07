#!/usr/bin/env python3
"""Fail-closed check that a published dataset carries no machine identifiers.

This is the gate that lets us say "derived features only, no identifiers" about
``eval/data/`` and mean it. It walks every JSON leaf of every record and rejects
anything that looks like a stable hardware or network identifier:

* MAC addresses (``aa:bb:cc:dd:ee:ff``)
* ``/etc/machine-id``-shaped values that are NOT a known random field
* CPU/board serial-number strings
* hostnames or user names
* a CPU *model* string (e.g. ``Ryzen 7 8845HS``); only the generic *vendor*
  (``AuthenticAMD`` / ``GenuineIntel`` / ``arm`` / ``ppc``) is allowed

Random per-run values that are *supposed* to be high-entropy hex -- the
challenge nonce, the payload digest, HMAC/MAC fields, and the seed-derived
kernel ``result`` samples -- are allowlisted by their JSON path so the 32/64-hex
rule does not false-positive on them. Everything else that is 32+ hex chars is
treated as suspicious.

Usage::

    python3 eval/verify_no_identifiers.py eval/data/local/*.jsonl
    # exit 0 = clean, exit 1 = at least one identifier found (printed)

Importable: ``scan_record(record) -> list[Finding]`` and ``scan_file(path)``.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
from typing import Any, Dict, Iterable, List, NamedTuple

# CPU model tokens that must never appear (generic vendor strings are fine).
_MODEL_TOKENS = re.compile(
    r"\b(ryzen|epyc|core\s*i[3579]|xeon|pentium|celeron|threadripper|"
    r"cortex|snapdragon|apple\s+m[1-9]|power\d|ultrasparc|"
    r"\d{3,4}hs?\b|\d{3,4}x\b|\d{3,4}k\b|\d{3,4}hx\b)",
    re.IGNORECASE,
)
_MAC = re.compile(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.IGNORECASE)
_SERIAL_KEY = re.compile(r"serial|uuid|hostname|host_name|username|user_name|machine_id", re.I)
_LONG_HEX = re.compile(r"^[0-9a-f]{32,}$", re.IGNORECASE)

# JSON-path *suffixes* whose value is legitimately high-entropy hex. Matched
# against the dotted path with ``[i]`` indices stripped, so a leaf is allowlisted
# regardless of its sample index.
_HEX_OK_SUFFIXES = (
    "challenge.nonce",
    "challenge.mac",
    "digest",
    "session.mac",
    ".result",  # kernel result samples: results.<mod>.samples[].result
)


class Finding(NamedTuple):
    path: str
    kind: str
    value: str


def _norm(path: str) -> str:
    return re.sub(r"\[\d+\]", "", path)


def _hex_allowlisted(path: str) -> bool:
    n = _norm(path)
    return any(n.endswith(s) for s in _HEX_OK_SUFFIXES)


def _walk(obj: Any, path: str) -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")
    else:
        yield path, obj


def scan_record(record: Dict[str, Any]) -> List[Finding]:
    """Return every identifier-shaped leaf in ``record`` (empty list == clean)."""
    out: List[Finding] = []
    for path, val in _walk(record, ""):
        key = path.rsplit(".", 1)[-1]
        if _SERIAL_KEY.search(key) and _norm(path) != "payload.ids.machine_id_rp":
            # a machine_id_rp would only appear if someone shipped it; the dataset
            # is built with --no-id, so even the salted id must be absent.
            out.append(Finding(path, "identifier_key", str(val)[:60]))
            continue
        if not isinstance(val, str):
            continue
        if _MAC.search(val):
            out.append(Finding(path, "mac_address", val[:60]))
        elif _MODEL_TOKENS.search(val):
            out.append(Finding(path, "cpu_model_string", val[:60]))
        elif _LONG_HEX.match(val) and not _hex_allowlisted(path):
            out.append(Finding(path, "unexplained_long_hex", val[:60]))
    return out


def scan_file(path: str) -> List[Finding]:
    out: List[Finding] = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            for fnd in scan_record(rec):
                out.append(Finding(f"{path}:{lineno}:{fnd.path}", fnd.kind, fnd.value))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", help="JSONL dataset files (globs ok)")
    a = ap.parse_args()
    paths: List[str] = []
    for pat in a.files:
        paths.extend(sorted(glob.glob(pat)) or [pat])
    findings: List[Finding] = []
    n_records = 0
    for p in paths:
        with open(p, encoding="utf-8") as f:
            n_records += sum(1 for line in f if line.strip())
        findings.extend(scan_file(p))
    if findings:
        print(f"IDENTIFIERS FOUND in {len(paths)} file(s), {n_records} record(s):")
        for fnd in findings:
            print(f"  [{fnd.kind}] {fnd.path} = {fnd.value!r}")
        return 1
    print(f"CLEAN: {n_records} record(s) across {len(paths)} file(s); "
          f"no machine identifiers found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

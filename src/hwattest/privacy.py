"""What leaves the machine.

Default payload = challenge echo + per-sample timings/results needed for
verification + derived, non-identifying features. Keys whose names start
with ``_`` (raw DMI strings, CPU model, the full CPU flag list) stay local
unless the user passes ``--share-raw``.
"""

from __future__ import annotations

import copy
from typing import Any, Dict


def split_raw(obj: Any, path: str = "") -> tuple[Any, Dict[str, Any]]:
    """Return (obj without '_'-keys, {dotted.path: removed value})."""
    removed: Dict[str, Any] = {}
    if isinstance(obj, dict):
        clean: Dict[str, Any] = {}
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if isinstance(k, str) and k.startswith("_"):
                removed[p] = v
                continue
            cv, rv = split_raw(v, p)
            clean[k] = cv
            removed.update(rv)
        return clean, removed
    if isinstance(obj, list):
        out = []
        for i, v in enumerate(obj):
            cv, rv = split_raw(v, f"{path}[{i}]")
            out.append(cv)
            removed.update(rv)
        return out, removed
    return obj, removed


def build_payload(
    challenge: Dict[str, Any], record: Dict[str, Any], share_raw: bool = False
) -> Dict[str, Any]:
    rec = copy.deepcopy(record)
    clean, raw = split_raw(rec)
    payload: Dict[str, Any] = {
        "challenge": challenge,
        "client": clean.get("client", {}),
        "session": clean.get("session", {}),
        "results": clean.get("results", {}),
        "share_raw": bool(share_raw),
    }
    if share_raw:
        payload["raw"] = raw
    return payload

"""One call from payload to verdict-free result: verify -> features -> scores."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

from ..measure import tpm
from .features import extract
from .scorer import score
from .verify import trace_hash, verify


def features_of(payload: Dict[str, Any]) -> Dict[str, Any]:
    if payload.get("mode") == "summary":
        return dict(payload.get("features") or {})
    return extract(payload)


def evaluate(
    payload: Dict[str, Any],
    authentic: Callable[[Dict[str, Any]], bool],
    store: Any,
    now: Optional[float] = None,
    allow_self: bool = False,
    offline: bool = False,
    spot_checks: int = 3,
) -> Dict[str, Any]:
    now = time.time() if now is None else now
    ver = verify(
        payload, authentic, store, now,
        spot_checks=spot_checks, allow_self=allow_self, offline=offline,
    )
    feats = features_of(payload)
    tpm_status = None
    q = ((payload.get("results") or {}).get("tpm") or {}).get("quote")
    if q:
        tpm_status = tpm.verify_quote(q, str((payload.get("challenge") or {}).get("nonce", "")))
    res = score(feats, ver, tpm_status=tpm_status)
    res["verification"] = ver
    res["trace_hash"] = trace_hash(payload.get("results") or {})
    return {"result": res, "features": feats}

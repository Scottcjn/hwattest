"""Glue: run a challenge's plan and wrap the result as a submittable payload."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Dict, Optional, Tuple

from .challenge import FORMAT, canonical
from .measure import run_plan
from .privacy import build_payload


def payload_digest(payload: Dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "digest"}
    return hashlib.sha256(canonical(body)).hexdigest()


def attest(
    challenge: Dict[str, Any],
    share_raw: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Run the plan in ``challenge``. Returns (payload_to_send, full_local_record)."""
    record = run_plan(challenge["plan"], nonce=str(challenge["nonce"]), progress=progress)
    payload = build_payload(challenge, record, share_raw=share_raw)
    payload["format"] = FORMAT
    payload["digest"] = payload_digest(payload)
    return payload, record

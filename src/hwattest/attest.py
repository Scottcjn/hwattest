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
    mode: str = "samples",
    no_id: bool = False,
    secret_path: Optional[str] = None,
    bind: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Run the plan in ``challenge``. Returns (payload_to_send, full_local_record)."""
    record = run_plan(challenge["plan"], nonce=str(challenge["nonce"]), progress=progress)
    payload = finalize(challenge, record, share_raw, mode, no_id, secret_path, bind)
    return payload, record


def finalize(
    challenge: Dict[str, Any],
    record: Dict[str, Any],
    share_raw: bool = False,
    mode: str = "samples",
    no_id: bool = False,
    secret_path: Optional[str] = None,
    bind: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the payload from an already-measured local record.

    ``bind``: an opaque hash (e.g. of a benchmark result) covered by the
    payload digest and therefore tied to this challenge's nonce.
    """
    payload = build_payload(
        challenge, record, share_raw=share_raw, mode=mode, no_id=no_id, secret_path=secret_path
    )
    if bind:
        payload["bind"] = str(bind)
    payload["format"] = FORMAT
    payload["digest"] = payload_digest(payload)
    return payload

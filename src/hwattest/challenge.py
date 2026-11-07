"""Challenge issuance and nonce bookkeeping.

A challenge = fresh 256-bit nonce + randomized measurement plan + validity
window, authenticated with an HMAC under the issuer's secret so the client
cannot choose (or pre-compute for) its own parameters. Nonces are single use.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import secrets
import threading
import time
from typing import Any, Dict, Optional, Set

from .plan import make_plan

FORMAT = "hwattest/0.1"
DEFAULT_TTL_S = 600.0


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _mac(secret: bytes, body: Dict[str, Any]) -> str:
    return hmac.new(secret, canonical(body), hashlib.sha256).hexdigest()


class MemoryStore:
    """Nonce + replay bookkeeping (in-memory). The server uses a SQLite one."""

    def __init__(self) -> None:
        self._issued: Dict[str, float] = {}
        self._used: Set[str] = set()
        self._trace_hashes: Dict[str, str] = {}
        self._lock = threading.Lock()

    def record_issued(self, nonce: str, expires_at: float) -> None:
        with self._lock:
            self._issued[nonce] = expires_at

    def consume(self, nonce: str) -> str:
        """Returns 'ok', 'unknown' or 'reused'."""
        with self._lock:
            if nonce in self._used:
                return "reused"
            if nonce not in self._issued:
                return "unknown"
            self._used.add(nonce)
            return "ok"

    def trace_seen(self, trace_hash: str, nonce: str) -> Optional[str]:
        """Remember a timing-trace hash; return the earlier nonce if seen before."""
        with self._lock:
            prev = self._trace_hashes.get(trace_hash)
            if prev is None:
                self._trace_hashes[trace_hash] = nonce
            return prev if prev != nonce else None


class Issuer:
    def __init__(
        self,
        secret: Optional[bytes] = None,
        store: Optional[Any] = None,
        ttl_s: float = DEFAULT_TTL_S,
        profile: str = "standard",
        issuer_id: str = "hwattest-server",
    ) -> None:
        self.secret = secret or secrets.token_bytes(32)
        self.store = store if store is not None else MemoryStore()
        self.ttl_s = ttl_s
        self.profile = profile
        self.issuer_id = issuer_id

    def issue(
        self,
        rp_id: str,
        profile: Optional[str] = None,
        tpm: bool = False,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = time.time() if now is None else now
        nonce = secrets.token_hex(32)
        # Plan randomness comes from the CSPRNG, not from anything the client knows.
        rng = random.Random(secrets.randbits(128))
        body: Dict[str, Any] = {
            "format": FORMAT,
            "issuer": self.issuer_id,
            "rp_id": rp_id,
            "nonce": nonce,
            "issued_at": round(now, 3),
            "expires_at": round(now + self.ttl_s, 3),
            "plan": make_plan(rng, profile or self.profile, tpm=tpm),
        }
        body["mac"] = _mac(self.secret, body)
        self.store.record_issued(nonce, body["expires_at"])
        return body

    def authentic(self, challenge: Dict[str, Any]) -> bool:
        mac = challenge.get("mac")
        if not isinstance(mac, str):
            return False
        body = {k: v for k, v in challenge.items() if k != "mac"}
        return hmac.compare_digest(mac, _mac(self.secret, body))


def self_challenge(rp_id: str = "local", profile: str = "standard") -> Dict[str, Any]:
    """Locally generated challenge for local-only use. Not verifiable by any RP."""
    now = time.time()
    return {
        "format": FORMAT,
        "issuer": "self",
        "rp_id": rp_id,
        "nonce": secrets.token_hex(32),
        "issued_at": round(now, 3),
        "expires_at": round(now + DEFAULT_TTL_S, 3),
        "plan": make_plan(random.Random(secrets.randbits(128)), profile),
        "mac": None,
    }

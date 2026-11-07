"""Small self-hostable HTTP service (stdlib ``http.server``).

Endpoints (JSON in / JSON out):

* ``GET  /v1/health``
* ``POST /v1/challenge``  ``{"rp_id"?, "profile"?, "tpm"?}`` -> challenge
* ``POST /v1/submit``     ``{"payload": {...}, "account"?: "..."}`` -> scores,
  reasons, verification, cluster
* ``GET  /v1/clusters?rp_id=..`` (``Authorization: Bearer <admin token>``)

One service can serve several relying parties (``--rp-id`` allow-list);
clustering is always per RP. Binds to 127.0.0.1 by default: put it behind your
own TLS reverse proxy to expose it.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..challenge import Issuer
from ..cluster.cluster import DEFAULT_IDENTICAL, DEFAULT_SAME_MACHINE, fingerprint, similarity
from ..score.pipeline import evaluate
from .store import SQLiteStore

MAX_BODY = 16 * 1024 * 1024


def _load_or_create_secret(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read()
            if len(data) >= 32:
                return data[:32]
    except OSError:
        pass
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


class Service:
    def __init__(
        self,
        data_dir: str,
        rp_ids: List[str],
        profile: str = "standard",
        retention_days: float = 30.0,
        admin_token: Optional[str] = None,
        same_machine: float = DEFAULT_SAME_MACHINE,
        identical: float = DEFAULT_IDENTICAL,
    ) -> None:
        if not rp_ids:
            raise ValueError("at least one rp_id is required")
        self.rp_ids = rp_ids
        self.store = SQLiteStore(os.path.join(data_dir, "hwattest.sqlite3"), retention_days)
        secret = _load_or_create_secret(os.path.join(data_dir, "issuer.key"))
        self.issuer = Issuer(secret=secret, store=self.store, profile=profile)
        self.admin_token = admin_token
        self.same_machine = same_machine
        self.identical = identical
        self._cluster_lock = threading.Lock()

    def challenge(self, req: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        rp = str(req.get("rp_id") or self.rp_ids[0])
        if rp not in self.rp_ids:
            return 400, {"error": "unknown rp_id"}
        profile = req.get("profile") or self.issuer.profile
        if profile not in ("standard", "quick"):
            return 400, {"error": "profile must be standard or quick"}
        return 200, self.issuer.issue(rp, profile=profile, tpm=bool(req.get("tpm")))

    def submit(self, req: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        payload = req.get("payload")
        if not isinstance(payload, dict):
            return 400, {"error": "payload missing"}
        rp = str((payload.get("challenge") or {}).get("rp_id", ""))
        if rp not in self.rp_ids:
            return 400, {"error": "unknown rp_id"}
        account = req.get("account")
        account = str(account)[:200] if account is not None else None
        try:
            ev = evaluate(payload, self.issuer.authentic, self.store)
        except Exception as e:  # malformed payloads must not take the server down
            return 400, {"error": f"unprocessable payload: {type(e).__name__}"}
        result = ev["result"]
        fp = fingerprint(ev["features"])
        accepted = bool(result["verification"]["accepted"])
        with self._cluster_lock:
            self.store.purge()
            cl = self._cluster_new(rp, fp, result["trace_hash"], account) if accepted else None
            sub_id = self.store.add_submission({
                "rp_id": rp,
                "account": account,
                "nonce": (payload.get("challenge") or {}).get("nonce"),
                "received_at": time.time(),
                "machine_id_rp": (payload.get("ids") or {}).get("machine_id_rp"),
                "bind": str(payload.get("bind"))[:128] if payload.get("bind") else None,
                "trace_hash": result["trace_hash"],
                "cluster_id": cl["cluster_id"] if cl else None,
                "fp": fp if accepted else None,
                "result": {"scores": result["scores"], "reasons": result["reasons"]},
            })
            if cl and cl.pop("_new_cluster", False):
                cl["cluster_id"] = f"c{sub_id}"
                self.store.set_cluster(sub_id, cl["cluster_id"])
        result["submission_id"] = sub_id
        result["cluster"] = cl
        result["bind"] = payload.get("bind")
        return 200, result

    def _cluster_new(
        self, rp: str, fp: Dict[str, Any], th: str, account: Optional[str]
    ) -> Dict[str, Any]:
        """Incremental single-link clustering against this RP's history."""
        prior = [p for p in self.store.submissions(rp) if p["fp"]]
        linked: Dict[str, float] = {}
        best: Tuple[float, Optional[Dict[str, Any]]] = (0.0, None)
        flags: List[str] = []
        accounts = {account} if account else set()
        for p in prior:
            s, _ = similarity(fp, p["fp"])
            if s > best[0]:
                best = (s, p)
            if s >= self.same_machine and p["cluster_id"]:
                linked[p["cluster_id"]] = max(linked.get(p["cluster_id"], 0.0), s)
            if s >= self.identical and "suspiciously_identical_fingerprint" not in flags:
                flags.append("suspiciously_identical_fingerprint")
            if th and p["trace_hash"] == th and "identical_timing_trace" not in flags:
                flags.append("identical_timing_trace")
        out: Dict[str, Any] = {
            "nearest": None if best[1] is None else {
                "submission_id": best[1]["id"], "similarity": round(best[0], 3)},
            "flags": flags,
        }
        if not linked:
            out.update({"_new_cluster": True, "cluster_id": None, "cluster_size": 1,
                        "distinct_accounts": len(accounts), "confidence": 0.0})
            return out
        # Merge every linked cluster into the oldest one (ids are "c<first id>").
        keep = min(linked, key=lambda c: int(c[1:]) if c[1:].isdigit() else 0)
        self.store.relabel_clusters(rp, [c for c in linked if c != keep], keep)
        members = [p for p in prior if p["cluster_id"] in linked]
        accounts |= {p["account"] for p in members if p["account"]}
        out.update({
            "cluster_id": keep,
            "cluster_size": len(members) + 1,
            "distinct_accounts": len(accounts),
            "confidence": round(max(linked.values()), 3),
        })
        if len(accounts) > 1:
            out["flags"].append("same_machine_multiple_accounts")
        return out

    def clusters(self, rp: str) -> Dict[str, Any]:
        groups: Dict[str, Dict[str, Any]] = {}
        for p in self.store.submissions(rp):
            if not p["cluster_id"]:
                continue
            g = groups.setdefault(p["cluster_id"], {"size": 0, "accounts": set()})
            g["size"] += 1
            if p["account"]:
                g["accounts"].add(p["account"])
        return {
            "rp_id": rp,
            "clusters": [
                {"cluster_id": k, "size": v["size"], "distinct_accounts": len(v["accounts"])}
                for k, v in sorted(groups.items(), key=lambda kv: -kv[1]["size"])
            ],
        }


def make_handler(svc: Service) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"hwattest/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # quieter default log
            pass

        def _send(self, code: int, obj: Dict[str, Any]) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Optional[Dict[str, Any]]:
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return None
            if n <= 0 or n > MAX_BODY:
                return None
            try:
                obj = json.loads(self.rfile.read(n))
            except (ValueError, UnicodeDecodeError):
                return None
            return obj if isinstance(obj, dict) else None

        def do_GET(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            if u.path == "/v1/health":
                self._send(200, {"ok": True, "version": __version__, "rp_ids": svc.rp_ids})
                return
            if u.path == "/v1/clusters":
                auth = self.headers.get("Authorization", "")
                tok = svc.admin_token
                if not tok or not hmac.compare_digest(auth, f"Bearer {tok}"):
                    self._send(401, {"error": "admin token required"})
                    return
                rp = (parse_qs(u.query).get("rp_id") or [svc.rp_ids[0]])[0]
                if rp not in svc.rp_ids:
                    self._send(400, {"error": "unknown rp_id"})
                    return
                self._send(200, svc.clusters(rp))
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            u = urlparse(self.path)
            body = self._body()
            if body is None:
                self._send(400, {"error": "expected a JSON object body (<= 16 MiB)"})
                return
            if u.path == "/v1/challenge":
                self._send(*svc.challenge(body))
            elif u.path == "/v1/submit":
                self._send(*svc.submit(body))
            else:
                self._send(404, {"error": "not found"})

    return Handler


def make_server(svc: Service, host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(svc))
    httpd.daemon_threads = True
    return httpd

"""SQLite persistence for the self-hosted service.

Stores issued/used nonces, timing-trace hashes (replay detection) and
submissions: scores + reasons, the derived fingerprint vector, cluster id, the
salted per-RP machine ID and the optional bound result hash. Per-sample
timings and any --share-raw fields are NOT stored. Rows older than
``retention_days`` are purged on startup and on every submit.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS issued (nonce TEXT PRIMARY KEY, rp_id TEXT, issued_at REAL,
                                   expires_at REAL);
CREATE TABLE IF NOT EXISTS used (nonce TEXT PRIMARY KEY, used_at REAL);
CREATE TABLE IF NOT EXISTS traces (hash TEXT PRIMARY KEY, nonce TEXT, seen_at REAL);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rp_id TEXT NOT NULL,
    account TEXT,
    nonce TEXT,
    received_at REAL NOT NULL,
    machine_id_rp TEXT,
    bind TEXT,
    trace_hash TEXT,
    cluster_id TEXT,
    fp TEXT,
    result TEXT
);
CREATE INDEX IF NOT EXISTS sub_rp ON submissions(rp_id, received_at);
"""


class SQLiteStore:
    def __init__(self, path: str, retention_days: float = 30.0) -> None:
        self.path = path
        self.retention_days = retention_days
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self.purge()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- nonce / replay interface (used by verify) ---------------------------
    def record_issued(self, nonce: str, expires_at: float, rp_id: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO issued VALUES (?,?,?,?)",
                (nonce, rp_id, time.time(), expires_at),
            )

    def consume(self, nonce: str) -> str:
        with self._lock:
            if self._db.execute("SELECT 1 FROM used WHERE nonce=?", (nonce,)).fetchone():
                return "reused"
            if not self._db.execute("SELECT 1 FROM issued WHERE nonce=?", (nonce,)).fetchone():
                return "unknown"
            self._db.execute("INSERT INTO used VALUES (?,?)", (nonce, time.time()))
            return "ok"

    def trace_seen(self, trace_hash: str, nonce: str) -> Optional[str]:
        with self._lock:
            row = self._db.execute(
                "SELECT nonce FROM traces WHERE hash=?", (trace_hash,)
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO traces VALUES (?,?,?)", (trace_hash, nonce, time.time())
                )
                return None
            return None if row[0] == nonce else str(row[0])

    # ---- submissions ---------------------------------------------------------
    def add_submission(self, row: Dict[str, Any]) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO submissions (rp_id, account, nonce, received_at, machine_id_rp, bind,"
                " trace_hash, cluster_id, fp, result) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    row["rp_id"], row.get("account"), row.get("nonce"), row["received_at"],
                    row.get("machine_id_rp"), row.get("bind"), row.get("trace_hash"),
                    row.get("cluster_id"), json.dumps(row.get("fp")), json.dumps(row.get("result")),
                ),
            )
            return int(cur.lastrowid or 0)

    def set_cluster(self, sub_id: int, cluster_id: str) -> None:
        with self._lock:
            self._db.execute("UPDATE submissions SET cluster_id=? WHERE id=?", (cluster_id, sub_id))

    def relabel_clusters(self, rp_id: str, old: List[str], new: str) -> None:
        if not old:
            return
        with self._lock:
            q = ",".join("?" for _ in old)
            self._db.execute(
                f"UPDATE submissions SET cluster_id=? WHERE rp_id=? AND cluster_id IN ({q})",
                [new, rp_id, *old],
            )

    def submissions(self, rp_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, account, received_at, machine_id_rp, trace_hash, cluster_id, fp"
                " FROM submissions WHERE rp_id=? ORDER BY id",
                (rp_id,),
            ).fetchall()
        return [
            {
                "id": r[0], "account": r[1], "received_at": r[2], "machine_id_rp": r[3],
                "trace_hash": r[4], "cluster_id": r[5], "fp": json.loads(r[6] or "null"),
            }
            for r in rows
        ]

    def purge(self) -> int:
        cutoff = time.time() - self.retention_days * 86400
        with self._lock:
            n = 0
            for table, col in (("issued", "issued_at"), ("used", "used_at"),
                               ("traces", "seen_at"), ("submissions", "received_at")):
                cur = self._db.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
                n += cur.rowcount or 0
            return n

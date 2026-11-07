"""What leaves the machine, and the per-relying-party machine ID.

Default payload ("samples" mode):
  * the challenge echo,
  * one tuple per challenge sample: (index, parameters, start offset, duration,
    kernel result). These are the responses to the randomized challenge and are
    what lets the verifier detect replays; they contain no identifiers,
  * derived, non-identifying features (VM indicator *categories*, SIMD-relevant
    flags, logical CPU count, CPU vendor, arch),
  * a salted per-RP machine ID (omit with ``no_id=True``).

Never sent: keys starting with ``_`` (raw DMI strings, CPU model string, the
full CPU flag list) unless ``share_raw=True``; the raw clock-read delta list
and MONOTONIC_RAW pairs are never even stored.

"summary" mode sends only client-computed features (no per-sample data). The
server cannot verify such a submission against the challenge and scores its
integrity as unverified.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import os
import secrets
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

ID_SCHEME = "hmac-sha256(local_secret, 'hwattest-machine-id/v1|' + rp_id + '|' + os_machine_id)"


def default_secret_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "hwattest", "secret")


def local_secret(path: Optional[str] = None, create: bool = True) -> Optional[bytes]:
    """Random per-installation secret (0600). Delete the file to rotate all IDs."""
    path = path or default_secret_path()
    try:
        with open(path, "rb") as f:
            data = f.read()
            if len(data) >= 32:
                return data[:32]
    except OSError:
        pass
    if not create:
        return None
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    data = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return data


def os_machine_id() -> str:
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(p) as f:
                v = f.read().strip()
                if v:
                    return v
        except OSError:
            pass
    if sys.platform == "darwin":
        try:
            out = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    return line.split("=")[-1].strip().strip('"')
        except (OSError, subprocess.SubprocessError):
            pass
    return ""


def machine_id_for_rp(rp_id: str, secret: bytes, machine_id: Optional[str] = None) -> str:
    mid = os_machine_id() if machine_id is None else machine_id
    msg = f"hwattest-machine-id/v1|{rp_id}|{mid}".encode()
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32]


def split_raw(obj: Any, path: str = "") -> Tuple[Any, Dict[str, Any]]:
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
    challenge: Dict[str, Any],
    record: Dict[str, Any],
    share_raw: bool = False,
    mode: str = "samples",
    no_id: bool = False,
    secret_path: Optional[str] = None,
) -> Dict[str, Any]:
    if mode not in ("samples", "summary"):
        raise ValueError("mode must be 'samples' or 'summary'")
    rec = copy.deepcopy(record)
    clean, raw = split_raw(rec)
    payload: Dict[str, Any] = {
        "challenge": challenge,
        "client": clean.get("client", {}),
        "share_raw": bool(share_raw),
        "mode": mode,
    }
    if mode == "samples":
        payload["session"] = clean.get("session", {})
        payload["results"] = clean.get("results", {})
    else:
        from .score.features import extract  # local import: avoid cycle

        payload["features"] = extract(clean)
        payload["session"] = {"elapsed_ns": clean.get("session", {}).get("elapsed_ns")}
    if not no_id:
        secret = local_secret(secret_path)
        if secret is not None:
            payload["ids"] = {
                "machine_id_rp": machine_id_for_rp(str(challenge.get("rp_id", "")), secret),
                "scheme": ID_SCHEME,
            }
    if share_raw:
        payload["raw"] = raw
    return payload


def describe(payload: Dict[str, Any], record: Dict[str, Any]) -> List[str]:
    """Human-readable account of what is sent vs kept local (for ``inspect``)."""
    _, raw = split_raw(record)
    lines = [
        f"mode: {payload.get('mode')}  (samples = per-challenge timings for verification;"
        " summary = derived features only, unverifiable)",
        f"relying party: {payload.get('challenge', {}).get('rp_id')}",
        "machine id sent: "
        + (payload["ids"]["machine_id_rp"] if payload.get("ids") else "none (--no-id)")
        + "  [salted per RP; delete ~/.config/hwattest/secret to rotate]",
    ]
    res = payload.get("results") or {}
    for mod in ("clock", "cache", "jitter", "simd"):
        n = len((res.get(mod) or {}).get("samples") or [])
        if n:
            lines.append(f"  {mod}: {n} samples (index, params, start_ns, duration_ns, result)")
    vm = ((res.get("vm") or {}).get("features")) or (payload.get("features") or {}).get("vm")
    if vm:
        lines.append("  vm/hypervisor features (categories only): " + ", ".join(sorted(vm)))
    if payload.get("raw"):
        lines.append("SHARED RAW (--share-raw): " + ", ".join(sorted(payload["raw"])))
    else:
        lines.append("kept local (not sent):")
        for k, v in sorted(raw.items()):
            shown = v if not isinstance(v, list) else f"[{len(v)} items]"
            lines.append(f"  {k} = {shown!r}")
    return lines

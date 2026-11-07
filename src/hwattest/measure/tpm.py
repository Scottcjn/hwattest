"""Optional TPM 2.0 quote via tpm2-tools.

Off unless the plan asks for it (``plan["tpm"]["quote"]``) *and* the tools and
device are usable by the current (non-root) user. Detection never fails the
measurement.

Honest limits (v0.1):
* The attestation key (AK) is created fresh per run and is **not** chained to
  the endorsement-key certificate, so a verified quote shows only that *some*
  TPM (possibly a VM's virtual TPM, e.g. swtpm) signed this nonce. The EK
  certificate is a globally unique identifier, so we deliberately do not send
  it; credential activation against the EK is future work.
* Apple Secure Enclave / DeviceCheck needs app entitlements and is not
  implemented.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
from typing import Any, Callable, Dict, List, Optional

TOOLS = ["tpm2_createek", "tpm2_createak", "tpm2_quote"]
DEVICES = ["/dev/tpmrm0", "/dev/tpm0"]
PCRS = "sha256:0,1,2,3,4,5,6,7"

Runner = Callable[[List[str], str], "subprocess.CompletedProcess[str]"]


def _default_runner(args: List[str], cwd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30)


def detect() -> Dict[str, Any]:
    devs = {
        d: {"exists": os.path.exists(d), "rw": os.access(d, os.R_OK | os.W_OK)} for d in DEVICES
    }
    tools = {t: shutil.which(t) is not None for t in TOOLS}
    usable_dev = next((d for d, s in devs.items() if s["exists"] and s["rw"]), None)
    return {
        "device_present": any(s["exists"] for s in devs.values()),
        "device_usable": usable_dev,
        "tools_present": all(tools.values()),
        "missing_tools": sorted(t for t, ok in tools.items() if not ok),
    }


def qualifying_data(nonce: str) -> str:
    """32-byte value bound into the quote: H("hwattest-tpm" | nonce)."""
    return hashlib.sha256(b"hwattest-tpm|" + nonce.encode()).hexdigest()


def run(
    params: Optional[Dict[str, Any]],
    nonce: str,
    runner: Optional[Runner] = None,
    workdir_parent: Optional[str] = None,
) -> Dict[str, Any]:
    info = detect()
    want = bool(params and params.get("quote"))
    out: Dict[str, Any] = {"detect": info, "requested": want, "quote": None}
    if not want:
        out["status"] = "not_requested"
        return out
    if runner is None:
        if not info["tools_present"]:
            out["status"] = "skipped_no_tools"
            return out
        if not info["device_usable"]:
            out["status"] = "skipped_no_device_access"
            return out
    run_ = runner or _default_runner
    parent = workdir_parent or os.path.join(os.path.expanduser("~"), ".cache", "hwattest")
    os.makedirs(parent, exist_ok=True)
    wd = tempfile.mkdtemp(prefix="tpm-", dir=parent)
    try:
        steps = [
            ["tpm2_createek", "-c", "ek.ctx", "-G", "rsa", "-u", "ek.pub"],
            ["tpm2_createak", "-C", "ek.ctx", "-c", "ak.ctx", "-G", "rsa", "-g", "sha256",
             "-s", "rsassa", "-u", "ak.pem", "-f", "pem"],
            ["tpm2_quote", "-c", "ak.ctx", "-l", PCRS, "-q", qualifying_data(nonce),
             "-m", "quote.msg", "-s", "quote.sig", "-o", "quote.pcrs", "-g", "sha256"],
        ]
        for args in steps:
            r = run_(args, wd)
            if r.returncode != 0:
                out["status"] = f"failed:{args[0]}"
                out["error"] = (r.stderr or "")[-300:]
                return out
        blobs = {}
        for name in ("ak.pem", "quote.msg", "quote.sig", "quote.pcrs"):
            p = os.path.join(wd, name)
            with open(p, "rb") as f:
                blobs[name.replace(".", "_")] = base64.b64encode(f.read()).decode()
        out["quote"] = blobs
        out["status"] = "quoted"
        return out
    except (OSError, subprocess.SubprocessError) as e:
        out["status"] = f"error:{type(e).__name__}"
        return out
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def verify_quote(quote: Dict[str, str], nonce: str, runner: Optional[Runner] = None) -> str:
    """Server-side check with tpm2_checkquote if installed. Returns a status."""
    if runner is None and not shutil.which("tpm2_checkquote"):
        return "unverified_no_tool"
    run_ = runner or _default_runner
    parent = os.path.join(os.path.expanduser("~"), ".cache", "hwattest")
    os.makedirs(parent, exist_ok=True)
    wd = tempfile.mkdtemp(prefix="tpmv-", dir=parent)
    try:
        for key, fn in (("ak_pem", "ak.pem"), ("quote_msg", "q.msg"),
                        ("quote_sig", "q.sig"), ("quote_pcrs", "q.pcrs")):
            with open(os.path.join(wd, fn), "wb") as f:
                f.write(base64.b64decode(quote[key]))
        r = run_(["tpm2_checkquote", "-u", "ak.pem", "-m", "q.msg", "-s", "q.sig",
                  "-f", "q.pcrs", "-g", "sha256", "-q", qualifying_data(nonce)], wd)
        return "verified_unchained_ak" if r.returncode == 0 else "invalid"
    except (OSError, KeyError, ValueError, subprocess.SubprocessError):
        return "invalid"
    finally:
        shutil.rmtree(wd, ignore_errors=True)

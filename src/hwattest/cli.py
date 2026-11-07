"""``hwattest measure | inspect | serve | score``.

Local-only by default: nothing touches the network unless ``--server`` is
given (measure/inspect) or you run ``serve``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from typing import Any, Dict, List, Optional

from . import __version__
from .attest import attest
from .challenge import MemoryStore, self_challenge
from .privacy import describe


def _post(url: str, obj: Dict[str, Any], timeout: float = 60.0) -> Dict[str, Any]:
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (user-given URL)
        out: Dict[str, Any] = json.loads(r.read())
        return out


def _challenge(args: argparse.Namespace) -> Dict[str, Any]:
    if args.server:
        req: Dict[str, Any] = {"profile": args.profile, "tpm": bool(args.tpm)}
        if args.rp:
            req["rp_id"] = args.rp
        return _post(args.server.rstrip("/") + "/v1/challenge", req)
    ch = self_challenge(args.rp or "local", args.profile)
    if args.tpm:
        ch["plan"]["tpm"]["quote"] = True
    return ch


def _progress(quiet: bool) -> Any:
    if quiet:
        return None
    return lambda name: print(f"  measuring {name} ...", file=sys.stderr)


def _measure_payload(args: argparse.Namespace) -> Dict[str, Any]:
    if getattr(args, "payload", None):
        with open(args.payload) as f:
            loaded: Dict[str, Any] = json.load(f)
            return loaded
    ch = _challenge(args)
    t = time.time()
    payload, record = attest(
        ch, share_raw=args.share_raw, progress=_progress(args.quiet),
        mode="summary" if args.summary else "samples", no_id=args.no_id, bind=args.bind,
    )
    if not args.quiet:
        print(f"  done in {time.time() - t:.1f}s", file=sys.stderr)
    args._record = record
    return payload


def cmd_measure(args: argparse.Namespace) -> int:
    payload = _measure_payload(args)
    if args.out:
        with open(args.out, "w") as f:
            json.dump(payload, f)
        print(f"payload written to {args.out}", file=sys.stderr)
    if not args.server:
        if not args.out:
            json.dump(payload, sys.stdout)
            print()
        print("local-only: nothing was sent (use --server URL to submit)", file=sys.stderr)
        return 0
    body: Dict[str, Any] = {"payload": payload}
    if args.account:
        body["account"] = args.account
    res = _post(args.server.rstrip("/") + "/v1/submit", body)
    _print_result(res, args.json)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    payload = _measure_payload(args)
    record = getattr(args, "_record", None) or {}
    print(json.dumps(payload, indent=1 if args.pretty else None))
    print("", file=sys.stderr)
    for line in describe(payload, record):
        print(line, file=sys.stderr)
    if args.save:
        with open(args.save, "w") as f:
            json.dump(payload, f)
        print(f"saved; submit unchanged with: hwattest measure --payload {args.save} "
              "--server URL", file=sys.stderr)
    print("nothing was sent.", file=sys.stderr)
    return 0


def _print_result(res: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(res, indent=1))
        return
    if "error" in res:
        print(f"error: {res['error']}")
        return
    print("scores:", json.dumps(res.get("scores")))
    ver = res.get("verification") or {}
    print("verification:", "accepted" if ver.get("accepted") else "REJECTED",
          ver.get("rejections") or "", ver.get("warnings") or "")
    for r in res.get("reasons", []):
        print(f"  [{r['dimension']}] {r['feature']}={r['value']!r} (w={r['weight']}): {r['text']}")
    if res.get("cluster") is not None:
        print("cluster:", json.dumps(res["cluster"]))


def cmd_score(args: argparse.Namespace) -> int:
    from .cluster.cluster import cluster, fingerprint
    from .score.pipeline import evaluate

    store = MemoryStore()
    items: List[Dict[str, Any]] = []
    outs: List[Dict[str, Any]] = []
    for path in args.files:
        with open(path) as f:
            payload = json.load(f)
        ev = evaluate(payload, lambda ch: False, store, allow_self=True, offline=True)
        res = ev["result"]
        res["file"] = path
        outs.append(res)
        if res["verification"]["accepted"]:
            items.append({"id": path, "fp": fingerprint(ev["features"]),
                          "trace_hash": res["trace_hash"]})
    clusters = {c["id"]: c for c in cluster(items)} if items else {}
    for res in outs:
        res["cluster"] = clusters.get(res["file"])
        if not args.json:
            print(f"== {res['file']}  (offline: challenge MAC / nonce / time window unchecked)")
        _print_result(res, args.json)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .server.app import Service, make_server

    data_dir = args.data_dir or os.path.join(os.path.expanduser("~"), ".local", "share", "hwattest")
    token: Optional[str] = None
    if args.admin_token_file:
        with open(args.admin_token_file) as f:
            token = f.read().strip()
    svc = Service(data_dir, args.rp_id or ["default"], profile=args.profile,
                  retention_days=args.retention_days, admin_token=token)
    httpd = make_server(svc, args.host, args.port)
    print(f"hwattest {__version__} serving on http://{args.host}:{httpd.server_address[1]} "
          f"rp_ids={svc.rp_ids} data={data_dir} retention={args.retention_days}d",
          file=sys.stderr, flush=True)
    deadline = time.time() + args.max_seconds if args.max_seconds else None
    httpd.timeout = 0.5
    try:
        while deadline is None or time.time() < deadline:
            httpd.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        svc.store.close()
    return 0


def _add_measure_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--server", help="hwattest service URL; omit for local-only")
    p.add_argument("--rp", help="relying-party id (default: the server's first, or 'local')")
    p.add_argument("--profile", default="standard", choices=["standard", "quick"])
    p.add_argument("--share-raw", action="store_true",
                   help="also send raw identifying strings (DMI, CPU model, full flag list)")
    p.add_argument("--summary", action="store_true",
                   help="send derived features only, no per-sample timings (unverifiable)")
    p.add_argument("--no-id", action="store_true", help="omit the salted per-RP machine id")
    p.add_argument("--tpm", action="store_true", help="request an (optional) TPM quote")
    p.add_argument("--bind", help="hex hash to bind into the payload (e.g. a benchmark result)")
    p.add_argument("--payload", help="use a payload saved by 'inspect --save' instead of measuring")
    p.add_argument("--quiet", action="store_true")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="hwattest", description=__doc__)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("measure", help="measure this machine (and submit with --server)")
    _add_measure_opts(m)
    m.add_argument("--out", help="write the payload JSON here")
    m.add_argument("--account", help="RP-side account name to attach on submit")
    m.add_argument("--json", action="store_true", help="print the server result as JSON")
    m.set_defaults(func=cmd_measure)

    i = sub.add_parser("inspect", help="show exactly what would be sent; sends nothing")
    _add_measure_opts(i)
    i.add_argument("--save", help="save the payload for a later 'measure --payload'")
    i.add_argument("--pretty", action="store_true")
    i.set_defaults(func=cmd_inspect)

    s = sub.add_parser("serve", help="run the self-hostable scoring service")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    s.add_argument("--data-dir")
    s.add_argument("--rp-id", action="append", help="allowed relying-party id (repeatable)")
    s.add_argument("--profile", default="standard", choices=["standard", "quick"])
    s.add_argument("--retention-days", type=float, default=30.0)
    s.add_argument("--admin-token-file")
    s.add_argument("--max-seconds", type=float, default=0.0, help="exit after N seconds")
    s.set_defaults(func=cmd_serve)

    c = sub.add_parser("score", help="score saved payload files offline (and cluster them)")
    c.add_argument("files", nargs="+")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_score)

    args = ap.parse_args(argv)
    rc: int = args.func(args)
    return rc


if __name__ == "__main__":
    sys.exit(main())

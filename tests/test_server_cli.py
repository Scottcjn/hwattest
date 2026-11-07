import json
import threading
import urllib.error
import urllib.request

import pytest

from hwattest.attest import attest
from hwattest.cli import main
from hwattest.server.app import Service, make_server


def _post(base, path, obj):
    req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


@pytest.fixture()
def server(tmp_path):
    # Low same-machine threshold: this test checks clustering mechanics, not
    # calibration (quick-profile repeatability varies with host load).
    svc = Service(str(tmp_path / "data"), ["bounty-a", "bench-b"], profile="quick",
                  admin_token="tok", same_machine=0.2)
    httpd = make_server(svc, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    yield base, svc
    httpd.shutdown()
    httpd.server_close()
    svc.store.close()


def test_end_to_end_challenge_submit_cluster(server):
    base, svc = server
    with urllib.request.urlopen(base + "/v1/health") as r:
        assert json.loads(r.read())["ok"]
    results = []
    for acct in ("alice", "bob"):
        ch = _post(base, "/v1/challenge", {"rp_id": "bounty-a", "profile": "quick"})
        p, _ = attest(ch, bind="ab" * 32)
        res = _post(base, "/v1/submit", {"payload": p, "account": acct})
        assert res["verification"]["accepted"], res["verification"]
        assert set(res["scores"]) >= {"real_hardware", "vm", "emulator", "integrity"}
        assert res["bind"] == "ab" * 32
        results.append(res)
    # Same physical machine, two accounts -> one cluster, flagged.
    assert results[1]["cluster"]["cluster_id"] == results[0]["cluster"]["cluster_id"]
    assert "same_machine_multiple_accounts" in results[1]["cluster"]["flags"]
    # Replay of the first payload is rejected.
    again = _post(base, "/v1/submit", {"payload": p, "account": "carol"})
    assert not again["verification"]["accepted"]
    assert "nonce_reused" in again["verification"]["rejections"]
    # Admin cluster listing needs the token.
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(base + "/v1/clusters?rp_id=bounty-a")
    req = urllib.request.Request(base + "/v1/clusters?rp_id=bounty-a",
                                 headers={"Authorization": "Bearer tok"})
    with urllib.request.urlopen(req) as r:
        cl = json.loads(r.read())
    assert cl["clusters"][0]["size"] == 2 and cl["clusters"][0]["distinct_accounts"] == 2


def test_clusters_are_per_rp(server):
    base, _ = server
    for rp in ("bounty-a", "bench-b"):
        ch = _post(base, "/v1/challenge", {"rp_id": rp, "profile": "quick"})
        p, _ = attest(ch)
        res = _post(base, "/v1/submit", {"payload": p})
        assert res["cluster"]["cluster_size"] == 1  # never sees the other RP's data


def test_bad_requests(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(base, "/v1/challenge", {"rp_id": "nope"})
    assert e.value.code == 400
    res = _post(base, "/v1/submit", {"payload": {"challenge": {"rp_id": "bounty-a"}}})
    assert res["verification"]["accepted"] is False
    assert res["scores"]["real_hardware"] == 0.0
    assert res["cluster"] is None


def test_storage_has_no_samples_or_raw(server):
    base, svc = server
    ch = _post(base, "/v1/challenge", {"rp_id": "bounty-a", "profile": "quick"})
    p, _ = attest(ch, share_raw=True)
    _post(base, "/v1/submit", {"payload": p})
    with open(svc.store.path, "rb") as f:
        db = f.read()
    for v in (p.get("raw") or {}).values():
        if isinstance(v, str) and len(v) > 6:
            assert v.encode() not in db


def test_cli_local_measure_inspect_and_score(tmp_path, capsys):
    out = tmp_path / "p.json"
    assert main(["measure", "--profile", "quick", "--out", str(out), "--quiet"]) == 0
    assert "nothing was sent" in capsys.readouterr().err
    assert main(["inspect", "--profile", "quick", "--quiet", "--save",
                 str(tmp_path / "i.json")]) == 0
    cap = capsys.readouterr()
    assert json.loads(cap.out)["challenge"]["issuer"] == "self"
    assert "kept local (not sent):" in cap.err
    assert main(["score", str(out), str(tmp_path / "i.json"), "--json"]) == 0
    text = capsys.readouterr().out
    assert '"real_hardware"' in text and '"cluster"' in text

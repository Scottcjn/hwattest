import json
import os
import stat
import time

import pytest

from hwattest import privacy
from hwattest.attest import attest, finalize
from hwattest.challenge import Issuer, self_challenge
from hwattest.score.verify import verify


@pytest.fixture(scope="module")
def measured():
    ch = self_challenge("rp-a", "tiny")
    _, record = attest(ch, no_id=True)
    return ch, record


def _raw_strings(record):
    _, raw = privacy.split_raw(record)
    vals = []
    for v in raw.values():
        if isinstance(v, str) and len(v) >= 4:
            vals.append(v)
        if isinstance(v, dict):
            vals += [x for x in v.values() if isinstance(x, str) and len(x) >= 4]
    return raw, vals


def test_default_payload_contains_no_raw_identifiers(measured, tmp_path):
    ch, record = measured
    raw, vals = _raw_strings(record)
    assert raw, "expected some locally-held raw fields on this platform"
    p = finalize(ch, record, secret_path=str(tmp_path / "s"))
    blob = json.dumps(p)
    for v in vals:
        if v.lower() not in ("none", "true", "false"):
            assert v not in blob, f"raw value leaked: {v!r}"
    assert "raw" not in p
    assert p["share_raw"] is False


def test_share_raw_includes_them(measured, tmp_path):
    ch, record = measured
    p = finalize(ch, record, share_raw=True, secret_path=str(tmp_path / "s"))
    assert p["raw"]
    assert any(k.endswith("_all_flags") or "cpu_model" in k for k in p["raw"])


def test_machine_id_is_per_rp_stable_and_rotatable(tmp_path):
    path = str(tmp_path / "cfg" / "secret")
    s1 = privacy.local_secret(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    a1 = privacy.machine_id_for_rp("rp-a", s1, machine_id="m")
    a2 = privacy.machine_id_for_rp("rp-a", privacy.local_secret(path), machine_id="m")
    b1 = privacy.machine_id_for_rp("rp-b", s1, machine_id="m")
    assert a1 == a2 and a1 != b1
    os.remove(path)
    assert privacy.machine_id_for_rp("rp-a", privacy.local_secret(path), machine_id="m") != a1


def test_machine_id_does_not_contain_os_machine_id(tmp_path):
    mid = privacy.os_machine_id() or "0123456789abcdef"
    s = privacy.local_secret(str(tmp_path / "s"))
    out = privacy.machine_id_for_rp("rp", s, machine_id=mid)
    assert mid not in out and len(out) == 32


def test_no_id_option(measured):
    ch, record = measured
    assert "ids" not in finalize(ch, record, no_id=True)


def test_summary_mode_sends_no_samples_and_is_unverifiable():
    iss = Issuer(profile="tiny")
    ch = iss.issue("rp-a")
    p, _ = attest(ch, mode="summary", no_id=True)
    assert "results" not in p and "features" in p
    assert "samples" not in json.dumps(p["features"])
    v = verify(p, iss.authentic, iss.store, time.time())
    assert v["accepted"] and v["integrity"] == 0.3
    assert "summary_only_unverifiable" in v["warnings"]


def test_describe_lists_kept_local(measured, tmp_path):
    ch, record = measured
    p = finalize(ch, record, secret_path=str(tmp_path / "s"))
    lines = "\n".join(privacy.describe(p, record))
    assert "kept local (not sent):" in lines
    assert "machine id sent:" in lines

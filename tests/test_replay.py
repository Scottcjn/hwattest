import copy
import time

import pytest

from hwattest.attest import attest, payload_digest
from hwattest.challenge import Issuer, self_challenge
from hwattest.score.verify import verify

from .forge import relabel


@pytest.fixture(scope="module")
def issuer():
    return Issuer(profile="quick")


@pytest.fixture(scope="module")
def recorded(issuer):
    ch = issuer.issue("rp-test")
    payload, _ = attest(ch)
    return payload


def _v(issuer, p, now=None, **kw):
    return verify(p, issuer.authentic, issuer.store, time.time() if now is None else now, **kw)


def test_fresh_run_accepted_then_replay_rejected(issuer):
    ch = issuer.issue("rp-test")
    p, _ = attest(ch)
    first = _v(issuer, p)
    assert first["accepted"], first
    again = _v(issuer, p)
    assert not again["accepted"]
    assert "nonce_reused" in again["rejections"]


def test_recorded_trace_under_new_challenge_rejected(issuer, recorded):
    p = copy.deepcopy(recorded)
    p["challenge"] = issuer.issue("rp-test")
    p["digest"] = payload_digest(p)
    v = _v(issuer, p)
    assert not v["accepted"]
    assert any(r.endswith(("param_mismatch", "result_mismatch", "not_plan_prefix"))
               for r in v["rejections"]), v["rejections"]


def test_relabelled_trace_with_honest_results_rejected(issuer, recorded):
    forged = relabel(recorded, issuer.issue("rp-test"), mode="index")
    v = _v(issuer, forged)
    assert not v["accepted"]
    assert sum(r.endswith("durations_do_not_track_parameters") for r in v["rejections"]) >= 2


def test_rank_sorted_relabel_rejected_as_synthetic(issuer, recorded):
    forged = relabel(recorded, issuer.issue("rp-test"), mode="rank")
    v = _v(issuer, forged)
    assert not v["accepted"]
    assert "synthetic_monotone_timings" in v["rejections"]


def test_known_bypass_rank_relabel_with_noise_is_not_detected(issuer, recorded):
    """KNOWN OPEN BYPASS (documented in README): an attacker who models the
    checks (re-executes kernels for results, rank-maps recorded timings onto the
    new parameters and adds noise) passes v0.1 verification. Clustering then
    sees the forged machine as the *same* machine as the recorded one."""
    forged = relabel(recorded, issuer.issue("rp-test"), mode="rank", noise=0.12, seed=7)
    v = _v(issuer, forged)
    assert v["accepted"], v


def test_tampered_payload_digest(issuer):
    ch = issuer.issue("rp-test")
    p, _ = attest(ch)
    p["results"]["jitter"]["samples"][0][4] += 1
    assert "digest_mismatch" in _v(issuer, p)["rejections"]


def test_client_chosen_plan_rejected(issuer):
    ch = issuer.issue("rp-test")
    ch["plan"]["cache"]["items"] = ch["plan"]["cache"]["items"][:1]
    p, _ = attest(ch)
    assert "challenge_not_authentic" in _v(issuer, p)["rejections"]


def test_unknown_nonce_and_expiry(issuer):
    other = Issuer(secret=issuer.secret, profile="tiny")  # same key, different store
    ch = other.issue("rp-test")
    p, _ = attest(ch)
    v = _v(issuer, p, now=ch["expires_at"] + 1)
    assert "nonce_unknown" in v["rejections"]
    assert "challenge_expired" in v["rejections"]


def test_claiming_more_time_than_server_saw(issuer):
    ch = issuer.issue("rp-test")
    p, _ = attest(ch)
    p["session"]["elapsed_ns"] = int(60e9)
    p["digest"] = payload_digest(p)
    v = _v(issuer, p, now=ch["issued_at"] + 1.0)
    assert "claims_more_time_than_elapsed" in v["rejections"]


def test_fabricated_tiny_durations(issuer):
    ch = issuer.issue("rp-test")
    p, _ = attest(ch)
    for s in p["results"]["jitter"]["samples"]:
        s[4] = 5
    p["digest"] = payload_digest(p)
    v = _v(issuer, p)
    assert "jitter_implausibly_fast" in v["rejections"]


def test_self_issued_only_with_allow_self(issuer):
    ch = self_challenge("local", "tiny")
    p, _ = attest(ch)
    assert "self_issued_challenge" in _v(issuer, p)["rejections"]
    v = _v(issuer, p, allow_self=True)
    assert "self_issued_challenge" not in v["rejections"]

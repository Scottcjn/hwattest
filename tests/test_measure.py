import os
import random
import subprocess

from hwattest import _stats, workloads
from hwattest.measure import run_plan, tpm, vmind
from hwattest.measure.clock import describe_read_deltas
from hwattest.plan import expected_counts, make_plan
from hwattest.score import features


def test_stats_basics():
    xs = [1.0, 2.0, 3.0, 4.0, 100.0]
    assert _stats.median(xs) == 3.0
    assert _stats.mad(xs) == 1.0
    assert abs(_stats.spearman([1, 2, 3, 4], [10, 20, 30, 40]) - 1.0) < 1e-12
    assert abs(_stats.spearman([1, 2, 3, 4], [40, 30, 20, 10]) + 1.0) < 1e-12
    a, b = _stats.theil_sen([1, 2, 3, 4, 5], [3, 5, 7, 9, 1000])  # one outlier
    assert abs(b - 2.0) < 1e-9 and abs(a - 1.0) < 1e-9
    assert _stats.noisy_or([0.5, 0.5]) == 0.75
    assert _stats.gcd_list([20, 40, 60]) == 20
    assert _stats.interp(1.5, [1, 2], [10, 20]) == 15


def test_kernels_deterministic():
    for name, fn in workloads.JITTER_KERNELS.items():
        assert fn(42, 100)[1] == fn(42, 100)[1], name
        assert fn(42, 100)[1] != fn(43, 100)[1], name
    assert workloads.k_hashwork(7, 10)[1] == workloads.k_hashwork(7, 10)[1]
    assert workloads.k_chase(8192, 5, 64)[1] == workloads.k_chase(8192, 5, 64)[1]
    for op in workloads.NATIVE_OPS:
        assert workloads.k_native(op, 3, 512)[1] == workloads.k_native(op, 3, 512)[1]


def test_chase_is_single_cycle():
    size = 64 * 97
    arr = workloads.build_chase(size, 11)
    seen = set()
    i = 0
    for _ in range(97):
        seen.add(i)
        i = arr[i]
    assert i == 0 and len(seen) == 97


def test_read_delta_description():
    d = describe_read_deltas([0, 0, 20, 40, 20, 60])
    assert d["zero_frac"] == 2 / 6
    assert d["granularity_ns"] == 20
    assert d["min_ns"] == 0


def test_tiny_plan_runs_and_is_complete():
    plan = make_plan(random.Random(3), "tiny")
    rec = run_plan(plan, nonce="n")
    res = rec["results"]
    exp = expected_counts(plan)
    for mod, n in exp.items():
        assert len(res[mod]["samples"]) == n, mod
        assert res[mod]["truncated"] is False
    assert "features" in res["vm"]
    assert res["tpm"]["status"] == "not_requested"
    assert rec["session"]["elapsed_ns"] > 0


def test_module_deadline_truncates_gracefully():
    plan = make_plan(random.Random(3), "tiny")
    plan["module_budget_s"] = 0.0
    rec = run_plan(plan)
    for mod in ("clock", "cache", "jitter", "simd"):
        assert rec["results"][mod]["truncated"] is True
        assert rec["results"][mod]["samples"] == []


def test_vm_token_matching_is_category_not_raw():
    assert vmind.match_token("QEMU Standard PC (Q35 + ICH9, 2009)") == "qemu"
    assert vmind.match_token("innotek GmbH") == "innotek"
    assert vmind.match_token("Victus by HP Gaming Laptop") is None
    assert vmind.match_token("Google Pixelbook") is None  # bare-metal Google hw
    assert vmind.match_token(None) is None


def test_tpm_detect_and_skip_cleanly():
    out = tpm.run({"quote": True}, "nonce")
    assert out["status"] in {"skipped_no_tools", "skipped_no_device_access", "quoted"} or \
        out["status"].startswith("failed")
    assert tpm.run(None, "nonce")["status"] == "not_requested"


def test_tpm_quote_flow_with_fake_runner(tmp_path):
    calls = []

    def fake(args, cwd):
        calls.append(args[0])
        if args[0] == "tpm2_createak":
            with open(os.path.join(cwd, "ak.pem"), "wb") as f:
                f.write(b"PEM")
        if args[0] == "tpm2_quote":
            assert tpm.qualifying_data("abc") in args
            for fn in ("quote.msg", "quote.sig", "quote.pcrs"):
                with open(os.path.join(cwd, fn), "wb") as f:
                    f.write(fn.encode())
        return subprocess.CompletedProcess(args, 0, "", "")

    out = tpm.run({"quote": True}, "abc", runner=fake, workdir_parent=str(tmp_path))
    assert out["status"] == "quoted"
    assert set(out["quote"]) == {"ak_pem", "quote_msg", "quote_sig", "quote_pcrs"}
    assert calls == ["tpm2_createek", "tpm2_createak", "tpm2_quote"]
    assert os.listdir(tmp_path) == []  # work dir cleaned up
    assert tpm.verify_quote(out["quote"], "abc", runner=fake) == "verified_unchained_ak"


# ---- feature extractors on synthetic inputs -------------------------------- #
def test_fit_linear_recovers_slope():
    rnd = random.Random(1)
    ns = [rnd.randint(1000, 4000) for _ in range(60)]
    durs = [500 + 30 * n * (1 + rnd.uniform(-0.01, 0.01)) for n in ns]
    f = features.fit_linear(ns, durs)
    assert abs(f["per_op_ns"] - 30) < 1
    assert f["spearman"] > 0.95
    assert f["resid_rcv"] < 0.02


def test_cache_features_synthetic_knee():
    samples = []
    for i, log2 in enumerate(range(12, 27)):
        size = 2 ** log2
        ns_step = 20.0 if log2 < 20 else 20.0 + 10 * (log2 - 19)
        for rep in range(3):
            samples.append([i, rep, size, 1000, 0, int(ns_step * 1000), "x"])
    f = features.cache_features({"samples": samples})
    assert f["knee_log2"] is not None and 20 <= f["knee_log2"] <= 22
    assert abs(f["final_excess_ns"] - 70.0) < 1e-6
    assert f["monotonic_spearman"] > 0.8
    assert f["excess_grid"]["12"] == 0.0


def test_jitter_and_simd_features_synthetic():
    jit = []
    for i in range(40):
        n = 1000 + 100 * i
        jit.append([i, "int", n, 0, 40 * n, "x"])
        jit.append([i, "fp", n, 0, 60 * n, "x"])
    jf = features.jitter_features({"samples": jit})
    assert abs(jf["int"]["per_op_ns"] - 40) < 1e-6
    assert abs(jf["ratio_fp_int"] - 1.5) < 1e-6
    sim = []
    for i in range(10):
        size = 4096 * (i + 1)
        sim.append([i, "memcpy", size, 0, size // 10 + 100, "x"])   # 10 GB/s
        sim.append([i, "sha256", size, 0, size // 2 + 100, "x"])    # 2 GB/s
        sim.append([i, "sha512", size, 0, size + 100, "x"])         # 1 GB/s
    sf = features.simd_features({"samples": sim, "simd_flags": ["sha_ni"]})
    assert abs(sf["sha256_over_sha512"] - 2.0) < 0.05
    assert sf["profile"]["memcpy"] == 0.0
    assert sf["profile"]["sha256"] < 0


def test_extract_handles_empty_record():
    f = features.extract({})
    assert f["cache"]["points"] == 0
    assert f["cross"] == {}

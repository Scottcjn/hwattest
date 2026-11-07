import copy

from hwattest.cluster.cluster import cluster, fingerprint, similarity
from hwattest.score.scorer import score


def base_feats():
    grid = {str(g): (0.0 if g < 22 else 10.0 * (g - 21)) for g in range(12, 27)}
    return {
        "clock": {"read_min_ns": 30.0, "read_p50_ns": 40.0, "slew_ppm": 1.5,
                  "clocksource": "tsc"},
        "cache": {"max_log2": 26.0, "excess_ratio": 6.0, "excess_grid": grid,
                  "final_excess_ns": 50.0},
        "jitter": {"int": {"per_op_ns": 80.0, "resid_rcv": 0.02},
                   "fp": {"per_op_ns": 40.0, "resid_rcv": 0.02},
                   "ratio_fp_int": 0.5, "ratio_branch_int": 1.5, "ratio_ldst_int": 1.3},
        "simd": {"profile": {"memcpy": 4.0, "sha256": -0.7, "sha512": -1.7, "crc32": 0.5},
                 "log2_memcpy_over_sha256": 4.7, "sha256_over_sha512": 2.0,
                 "flags": ["avx2", "sha_ni", "sse2"]},
        "vm": {"arch": "x86_64", "cpu_vendor": "AuthenticAMD", "logical_cpus": 16,
               "clocksource": "tsc"},
        "cross": {"dram_excess_over_int_op": 1.0},
    }


def reasons_for(res, dim):
    return [r for r in res["reasons"] if r["dimension"] == dim]


def test_clean_bare_metal_scores_high_with_explicit_reason():
    res = score(base_feats(), {"integrity": 1.0, "rejections": [], "warnings": []})
    assert res["scores"]["real_hardware"] == 1.0
    assert res["scores"]["vm"] == 0.0
    assert res["reasons"][0]["feature"] == "none"


def test_vm_indicators_raise_vm_score_with_reasons():
    f = base_feats()
    f["vm"].update({"cpuid_hypervisor_flag": True, "clocksource_is_paravirtual": True,
                    "clocksource": "kvm-clock", "pci_vm_vendors": {"virtio": 6}})
    res = score(f)
    assert res["scores"]["vm"] > 0.95
    assert res["scores"]["real_hardware"] < 0.05
    feats = {r["feature"] for r in reasons_for(res, "vm")}
    assert {"cpuid_hypervisor_flag", "clocksource", "pci_vm_vendors"} <= feats
    assert all(r["text"] for r in res["reasons"])


def test_emulator_signals_from_timing_alone():
    """No VM strings at all (scrubbed), only timing physics."""
    f = base_feats()
    f["simd"]["log2_memcpy_over_sha256"] = 1.2
    f["simd"]["sha256_over_sha512"] = 1.1
    f["clock"]["read_min_ns"] = 1600.0
    res = score(f)
    assert res["scores"]["vm"] == 0.0
    assert res["scores"]["emulator"] > 0.9
    got = {r["feature"] for r in reasons_for(res, "emulator")}
    assert {"simd.log2_memcpy_over_sha256", "simd.sha256_over_sha512",
            "clock.read_min_ns"} <= got


def test_sha_ratio_only_counts_when_cpu_claims_sha_instructions():
    f = base_feats()
    f["simd"]["flags"] = ["avx2", "sse2"]
    f["simd"]["sha256_over_sha512"] = 0.65  # normal for x86 without SHA-NI
    res = score(f)
    assert res["scores"]["emulator"] == 0.0


def test_integrity_rejection_zeroes_real_hardware():
    res = score(base_feats(), {"integrity": 0.0, "rejections": ["nonce_reused"],
                               "warnings": []})
    assert res["scores"]["real_hardware"] == 0.0
    assert any(r["value"] == "nonce_reused" for r in res["reasons"])


def test_container_is_informational_not_a_vm():
    f = base_feats()
    f["vm"]["container_markers"] = ["dockerenv"]
    res = score(f)
    assert res["scores"]["container"] > 0.5
    assert res["scores"]["real_hardware"] == 1.0


def test_flat_cache_curve_lowers_plausibility():
    f = base_feats()
    f["cache"]["excess_ratio"] = 1.05
    res = score(f)
    assert res["scores"]["real_hardware"] < 1.0
    assert reasons_for(res, "real_hardware")


# ---- clustering ------------------------------------------------------------ #
def perturb(f, k):
    g = copy.deepcopy(f)
    g["jitter"]["int"]["per_op_ns"] *= 1 + 0.02 * k
    g["cache"]["excess_grid"]["24"] += 0.5 * k
    g["simd"]["profile"]["crc32"] += 0.03 * k
    return g


def other_machine(f):
    g = copy.deepcopy(f)
    g["cache"]["excess_grid"] = {str(x): (0.0 if x < 18 else 8.0 * (x - 17))
                                 for x in range(12, 27)}
    g["simd"]["profile"] = {"memcpy": 3.0, "sha256": -2.5, "sha512": -1.5, "crc32": 1.5}
    g["simd"]["flags"] = ["avx2", "sse2"]
    g["jitter"]["ratio_fp_int"] = 0.8
    return g


def test_similarity_same_vs_different_machine():
    a = fingerprint(base_feats())
    s_same, _ = similarity(a, fingerprint(perturb(base_feats(), 2)))
    s_diff, _ = similarity(a, fingerprint(other_machine(base_feats())))
    assert s_same > 0.7 > 0.3 > s_diff


def test_arch_mismatch_is_zero_similarity():
    b = base_feats()
    b["vm"]["arch"] = "aarch64"
    assert similarity(fingerprint(base_feats()), fingerprint(b))[0] == 0.0


def test_cluster_finds_one_machine_many_accounts_and_identical_traces():
    f = base_feats()
    items = [
        {"id": "s1", "account": "alice", "fp": fingerprint(perturb(f, 1)), "trace_hash": "t1"},
        {"id": "s2", "account": "bob", "fp": fingerprint(perturb(f, 2)), "trace_hash": "t2"},
        {"id": "s3", "account": "carol", "fp": fingerprint(other_machine(f)), "trace_hash": "t3"},
        {"id": "s4", "account": "dave", "fp": fingerprint(perturb(f, 1)), "trace_hash": "t1"},
    ]
    res = cluster(items)
    by = {r["id"]: r for r in res}
    assert by["s1"]["cluster_id"] == by["s2"]["cluster_id"] == by["s4"]["cluster_id"]
    assert by["s3"]["cluster_id"] != by["s1"]["cluster_id"]
    assert by["s1"]["cluster_size"] == 3 and by["s1"]["distinct_accounts"] == 3
    assert "same_machine_multiple_accounts" in by["s2"]["flags"]
    assert "identical_timing_trace" in by["s4"]["flags"]
    assert "suspiciously_identical_fingerprint" in by["s1"]["flags"]
    assert by["s3"]["cluster_size"] == 1 and by["s3"]["flags"] == []
    assert 0 < by["s1"]["confidence"] <= 1

"""Transparent heuristic scorer.

Each dimension is a probability-like score in [0, 1] built from named pieces
of evidence. Every piece that moved a score is returned as a reason with the
feature, its value, the weight it contributed and a plain-English
explanation. Thresholds are provisional, set from the local evaluation in
``eval/`` (sample sizes in README); they are deliberately conservative and
will move as fleet data arrives.

Dimensions:
* ``vm``        - likelihood the code ran inside a hardware-assisted VM
* ``emulator``  - likelihood of binary translation / full emulation (e.g. TCG)
* ``container`` - informational; a container on bare metal is still real hardware
* ``integrity`` - from challenge verification (1 = fresh, consistent execution)
* ``real_hardware`` - (1 - noisy_or(vm, emulator)) x integrity x plausibility
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .._stats import clamp01, noisy_or

Reason = Dict[str, Any]


def _r(dim: str, feature: str, value: Any, weight: float, text: str) -> Reason:
    return {
        "dimension": dim,
        "feature": feature,
        "value": value,
        "weight": round(weight, 3),
        "text": text,
    }


def vm_evidence(vm: Dict[str, Any]) -> List[Reason]:
    out: List[Reason] = []
    if vm.get("cpuid_hypervisor_flag"):
        out.append(_r("vm", "cpuid_hypervisor_flag", True, 0.9,
                      "CPUID reports a hypervisor is present"))
    if vm.get("macos_hv_vmm_present"):
        out.append(_r("vm", "macos_hv_vmm_present", True, 0.95,
                      "macOS reports it is running under a hypervisor"))
    dmi = vm.get("dmi_vm_tokens") or {}
    if dmi:
        out.append(_r("vm", "dmi_vm_tokens", dmi, 0.9,
                      "firmware (DMI/SMBIOS) strings name a virtual platform"))
    for key in ("cpu_model_vm_token", "hw_model_vm_token"):
        if vm.get(key):
            out.append(_r("vm", key, vm[key], 0.8, "CPU/model string names a virtual CPU"))
    if vm.get("clocksource_is_paravirtual"):
        out.append(_r("vm", "clocksource", vm.get("clocksource"), 0.85,
                      "kernel uses a paravirtual clock source"))
    if vm.get("sys_hypervisor_type"):
        out.append(_r("vm", "sys_hypervisor_type", vm["sys_hypervisor_type"], 0.9,
                      "/sys/hypervisor reports a hypervisor"))
    sdv = vm.get("systemd_detect_virt_vm")
    if sdv and sdv != "none":
        out.append(_r("vm", "systemd_detect_virt_vm", sdv, 0.9,
                      "systemd-detect-virt identifies a VM"))
    pci = vm.get("pci_vm_vendors") or {}
    if sum(pci.values()) >= 2:
        out.append(_r("vm", "pci_vm_vendors", pci, 0.6,
                      "several PCI devices from virtual-hardware vendors (virtio, QEMU, ...)"))
    if (vm.get("virtio_bus_devices") or 0) > 0:
        out.append(_r("vm", "virtio_bus_devices", vm["virtio_bus_devices"], 0.5,
                      "virtio bus devices present"))
    if vm.get("nic_vm_oui"):
        out.append(_r("vm", "nic_vm_oui", vm["nic_vm_oui"], 0.5,
                      "a physical-bus NIC has a MAC prefix assigned to a hypervisor vendor"))
    if (vm.get("steal_ticks") or 0) > 0:
        out.append(_r("vm", "steal_ticks", vm["steal_ticks"], 0.6,
                      "the kernel has accounted CPU steal time (only happens under a hypervisor)"))
    if vm.get("wsl"):
        out.append(_r("vm", "wsl", True, 0.9, "running under WSL2 (a Hyper-V VM)"))
    if vm.get("dmi_microsoft_virtual"):
        out.append(_r("vm", "dmi_microsoft_virtual", True, 0.9, "Hyper-V virtual machine"))
    return out


def emulator_evidence(f: Dict[str, Any]) -> List[Reason]:
    out: List[Reason] = []
    simd = f.get("simd") or {}
    clock = f.get("clock") or {}
    gap = simd.get("log2_memcpy_over_sha256")
    if gap is not None:
        # Real CPUs: libc memcpy runs >=8x faster than SHA-256 (log2 gap >= 3).
        # Under binary translation vectorised memcpy collapses towards hash speed.
        w = clamp01((3.0 - gap) / 1.5)
        if w > 0:
            out.append(_r("emulator", "simd.log2_memcpy_over_sha256", round(gap, 2), w,
                          "native vector memcpy is barely faster than SHA-256 "
                          "(flattened SIMD profile, typical of binary translation)"))

    flags = set(simd.get("flags") or [])
    ratio = simd.get("sha256_over_sha512")
    accel = "sha_ni" in flags or ("sha2" in flags and "sha512" not in flags)
    if ratio is not None and accel and ratio < 1.4:
        w = clamp01((1.4 - ratio) / 0.3)
        out.append(_r("emulator", "simd.sha256_over_sha512", round(ratio, 2), w,
                      "CPU advertises SHA-256 instructions but SHA-256 is not faster "
                      "than SHA-512 (instruction emulated in software?)"))

    rmin = clock.get("read_min_ns")
    if rmin is not None and rmin > 500:
        strong = clock.get("clocksource") == "tsc"
        out.append(_r("emulator", "clock.read_min_ns", rmin, 0.8 if strong else 0.35,
                      "reading the clock takes over 0.5 us"
                      + (" although the clocksource is the TSC" if strong else "")))

    slew = clock.get("slew_ppm")
    if slew is not None and abs(slew) > 200:
        out.append(_r("emulator", "clock.slew_ppm", slew, 0.4,
                      "oscillator correction above 200 ppm: implausible for a quartz "
                      "crystal, typical of an emulated timer"))

    cross = (f.get("cross") or {}).get("dram_excess_over_int_op")
    if cross is not None and cross < 0.4:
        # Weak on purpose: slow real CPUs (vintage) also have small ratios.
        out.append(_r("emulator", "cross.dram_excess_over_int_op", round(cross, 3),
                      0.3 * clamp01((0.4 - cross) / 0.3),
                      "interpreter is slow relative to physical DRAM latency"))
    return out


def plausibility(f: Dict[str, Any]) -> List[Reason]:
    out: List[Reason] = []
    cache = f.get("cache") or {}
    if (cache.get("max_log2") or 0) >= 23 and (cache.get("excess_ratio") or 0) < 1.5:
        out.append(_r("real_hardware", "cache.excess_ratio", round(cache["excess_ratio"], 2),
                      0.3, "no visible cache hierarchy in the latency curve"))
    jit = f.get("jitter") or {}
    rcvs: List[float] = [
        float(v["resid_rcv"])
        for v in jit.values()
        if isinstance(v, dict) and v.get("resid_rcv") is not None
    ]
    if rcvs and max(rcvs) < 0.0005:
        out.append(_r("real_hardware", "jitter.resid_rcv", round(max(rcvs), 6), 0.5,
                      "timings are implausibly uniform"))
    return out


def container_evidence(vm: Dict[str, Any]) -> List[Reason]:
    out: List[Reason] = []
    marks = vm.get("container_markers") or []
    sdc = vm.get("systemd_detect_virt_container")
    if marks:
        out.append(_r("container", "container_markers", marks, 0.8,
                      "container runtime markers present (not a VM by itself)"))
    if sdc and sdc != "none":
        out.append(_r("container", "systemd_detect_virt_container", sdc, 0.9,
                      "systemd-detect-virt identifies a container"))
    return out


def score(
    feats: Dict[str, Any],
    verification: Optional[Dict[str, Any]] = None,
    tpm_status: Optional[str] = None,
) -> Dict[str, Any]:
    vm_r = vm_evidence(feats.get("vm") or {})
    emu_r = emulator_evidence(feats)
    pl_r = plausibility(feats)
    ct_r = container_evidence(feats.get("vm") or {})

    vm_s = noisy_or([r["weight"] for r in vm_r])
    emu_s = noisy_or([r["weight"] for r in emu_r])
    cont_s = noisy_or([r["weight"] for r in ct_r])
    integ = 1.0 if verification is None else float(verification.get("integrity", 0.0))
    plaus = 1.0
    for r in pl_r:
        plaus *= 1.0 - r["weight"]
    real = (1.0 - noisy_or([vm_s, emu_s])) * integ * plaus

    reasons = vm_r + emu_r + pl_r + ct_r
    if verification is not None:
        for code in verification.get("rejections", []):
            reasons.append(_r("integrity", "verification", code, 1.0,
                              f"challenge verification failed: {code}"))
        for code in verification.get("warnings", []):
            reasons.append(_r("integrity", "verification", code, 0.15,
                              f"verification warning: {code}"))
    if tpm_status:
        reasons.append(_r("tpm", "tpm_quote", tpm_status, 0.0,
                          "TPM quote status (AK not chained to EK in v0.1: shows a TPM, "
                          "possibly virtual, signed the nonce; not scored)"))
    if not reasons:
        reasons.append(_r("real_hardware", "none", None, 0.0,
                          "no VM, emulator or integrity evidence found"))
    return {
        "scores": {
            "real_hardware": round(real, 3),
            "vm": round(vm_s, 3),
            "emulator": round(emu_s, 3),
            "container": round(cont_s, 3),
            "integrity": round(integ, 3),
        },
        "reasons": reasons,
        "note": "probabilistic score with reasons, not a proof; see README 'Honest limits'",
    }

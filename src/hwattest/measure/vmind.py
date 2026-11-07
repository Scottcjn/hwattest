"""VM / hypervisor / container indicators, reported as *features*, not verdicts.

Every indicator is a named feature with a category value (e.g. the matched
known-VM token), never the raw identifying string. Raw strings (DMI vendor and
product, CPU model) are collected into ``_raw`` and only shared with
``--share-raw``.

VM-hiding setups can remove all of these; that is why the scorer combines
them with timing evidence. Ported from Elyan Labs' earlier anti-emulation
check (Apache-2.0), with the cloud-metadata network probe removed (local-only
by default; no network traffic during measurement).
"""

from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Tokens that only appear on virtual platforms.
STRONG_VM_TOKENS = [
    "qemu", "kvm", "vmware", "virtualbox", "innotek", "xen", "bochs", "bhyve",
    "parallels", "virtual machine", "hvm domu", "openstack", "cloud hypervisor",
    "google compute engine", "amazon ec2", "droplet", "digitalocean", "linode",
    "vultr", "hetzner vserver", "alibaba cloud ecs", "apple virtualization",
    "virtualmac", "firecracker", "acrn", "standard pc (q35", "standard pc (i440fx",
]

DMI_FIELDS = [
    "sys_vendor", "product_name", "product_version", "board_vendor", "board_name",
    "bios_vendor", "bios_version", "chassis_vendor",
]

VM_CLOCKSOURCES = {
    "kvm-clock", "xen", "hyperv_clocksource_tsc_page", "hyperv_clocksource_msr",
    "vmware", "tsc-early-vm",
}

VM_PCI_VENDORS = {
    "0x1af4": "virtio",
    "0x1b36": "qemu",
    "0x15ad": "vmware",
    "0x80ee": "virtualbox",
    "0x1414": "hyperv",
    "0x5853": "xen",
    "0x1ab8": "parallels",
}

VM_MAC_OUIS = {
    "52:54:00": "qemu",
    "08:00:27": "virtualbox",
    "00:0c:29": "vmware",
    "00:50:56": "vmware",
    "00:05:69": "vmware",
    "00:15:5d": "hyperv",
    "00:16:3e": "xen",
    "00:1c:42": "parallels",
}


def _read(path: str, limit: int = 4096) -> Optional[str]:
    try:
        with open(path, errors="replace") as f:
            return f.read(limit).strip()
    except OSError:
        return None


def match_token(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    low = text.lower()
    for tok in STRONG_VM_TOKENS:
        if tok in low:
            return tok
    return None


def _run(args: List[str]) -> Optional[str]:
    if not shutil.which(args[0]):
        return None
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def read_steal_ticks() -> Optional[int]:
    """Aggregate steal ticks from /proc/stat (nonzero only under a hypervisor)."""
    txt = _read("/proc/stat", 1024)
    if not txt:
        return None
    parts = txt.splitlines()[0].split()
    if len(parts) > 8 and parts[0] == "cpu":
        try:
            return int(parts[8])
        except ValueError:
            return None
    return None


def cpu_model_string() -> str:
    txt = _read("/proc/cpuinfo", 65536) or ""
    for line in txt.splitlines():
        k = line.split(":", 1)[0].strip().lower()
        if k in ("model name", "cpu", "hardware", "processor") and ":" in line:
            v = line.split(":", 1)[1].strip()
            if v and not v.isdigit():
                return v
    if sys.platform == "darwin":
        return _run(["sysctl", "-n", "machdep.cpu.brand_string"]) or ""
    return platform.processor() or ""


def cpu_vendor() -> Optional[str]:
    txt = _read("/proc/cpuinfo", 8192) or ""
    for line in txt.splitlines():
        if line.lower().startswith("vendor_id") and ":" in line:
            return line.split(":", 1)[1].strip()
    if sys.platform == "darwin":
        return "Apple" if platform.machine() == "arm64" else "Intel"
    return None


def collect_linux() -> Dict[str, Any]:
    feats: Dict[str, Any] = {}
    raw: Dict[str, Any] = {}

    cpuinfo = _read("/proc/cpuinfo", 65536) or ""
    flags_line = ""
    for line in cpuinfo.splitlines():
        if line.lower().startswith(("flags", "features")):
            flags_line = line.lower()
            break
    feats["cpuid_hypervisor_flag"] = " hypervisor" in flags_line
    model = cpu_model_string()
    raw["cpu_model"] = model
    feats["cpu_model_vm_token"] = match_token(model)

    dmi_hits: Dict[str, str] = {}
    dmi_readable = 0
    for fld in DMI_FIELDS:
        v = _read(f"/sys/class/dmi/id/{fld}", 256)
        if v is None:
            continue
        dmi_readable += 1
        raw[f"dmi_{fld}"] = v
        tok = match_token(v)
        if tok:
            dmi_hits[fld] = tok
    feats["dmi_vm_tokens"] = dmi_hits
    feats["dmi_readable_fields"] = dmi_readable
    feats["dmi_microsoft_virtual"] = (
        (raw.get("dmi_sys_vendor") or "").lower().startswith("microsoft")
        and "virtual" in (raw.get("dmi_product_name") or "").lower()
    )

    hv = _read("/sys/hypervisor/type", 64)
    feats["sys_hypervisor_type"] = hv or None

    cs = _read("/sys/devices/system/clocksource/clocksource0/current_clocksource", 128)
    feats["clocksource"] = cs
    feats["clocksource_is_paravirtual"] = bool(cs and cs in VM_CLOCKSOURCES)

    pci_hits: Dict[str, int] = {}
    pci_total = 0
    for dev in glob.glob("/sys/bus/pci/devices/*"):
        pci_total += 1
        for fn in ("vendor", "subsystem_vendor"):
            v = _read(os.path.join(dev, fn), 16)
            if v and v.lower() in VM_PCI_VENDORS:
                name = VM_PCI_VENDORS[v.lower()]
                pci_hits[name] = pci_hits.get(name, 0) + 1
                break
    feats["pci_device_count"] = pci_total
    feats["pci_vm_vendors"] = pci_hits
    feats["virtio_bus_devices"] = len(glob.glob("/sys/bus/virtio/devices/*"))

    mac_hits: Dict[str, int] = {}
    for addr_file in glob.glob("/sys/class/net/*/address"):
        # Only NICs backed by a bus device: host bridges such as libvirt's
        # virbr0 carry a 52:54:00 MAC on bare metal and must not count.
        if not os.path.exists(os.path.join(os.path.dirname(addr_file), "device")):
            continue
        mac = (_read(addr_file, 64) or "").lower()
        oui = VM_MAC_OUIS.get(mac[:8])
        if oui:
            mac_hits[oui] = mac_hits.get(oui, 0) + 1
    feats["nic_vm_oui"] = mac_hits

    version = (_read("/proc/version", 512) or "").lower()
    feats["wsl"] = "microsoft" in version

    feats["systemd_detect_virt_vm"] = _run(["systemd-detect-virt", "--vm"])
    feats["systemd_detect_virt_container"] = _run(["systemd-detect-virt", "--container"])

    cgroup = (_read("/proc/1/cgroup", 4096) or "").lower()
    feats["container_markers"] = sorted(
        m
        for m, hit in (
            ("dockerenv", os.path.exists("/.dockerenv")),
            ("containerenv", os.path.exists("/run/.containerenv")),
            ("cgroup_docker", "docker" in cgroup),
            ("cgroup_kubepods", "kubepods" in cgroup),
            ("cgroup_lxc", "lxc" in cgroup),
            ("env_container", "container" in os.environ),
        )
        if hit
    )
    feats["steal_ticks"] = read_steal_ticks()
    return {"features": feats, "_raw": raw}


def collect_macos() -> Dict[str, Any]:
    feats: Dict[str, Any] = {}
    raw: Dict[str, Any] = {}
    hv = _run(["sysctl", "-n", "kern.hv_vmm_present"])
    feats["macos_hv_vmm_present"] = hv == "1"
    cpu_feats = (_run(["sysctl", "-n", "machdep.cpu.features"]) or "").upper()
    feats["cpuid_hypervisor_flag"] = "VMM" in cpu_feats.split()
    hw_model = _run(["sysctl", "-n", "hw.model"]) or ""
    raw["hw_model"] = hw_model
    feats["hw_model_vm_token"] = match_token(hw_model)
    model = cpu_model_string()
    raw["cpu_model"] = model
    feats["cpu_model_vm_token"] = match_token(model)
    feats["container_markers"] = []
    return {"features": feats, "_raw": raw}


def run(params: Optional[Dict[str, Any]] = None, ctx: Any = None) -> Dict[str, Any]:
    if sys.platform.startswith("linux"):
        out = collect_linux()
    elif sys.platform == "darwin":
        out = collect_macos()
    else:
        out = {"features": {"unsupported_platform": sys.platform}, "_raw": {}}
    out["features"]["arch"] = platform.machine().lower()
    out["features"]["os"] = platform.system()
    out["features"]["cpu_vendor"] = cpu_vendor()
    out["features"]["logical_cpus"] = os.cpu_count()
    return out

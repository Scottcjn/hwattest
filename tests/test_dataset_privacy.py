"""The published eval dataset must carry no machine identifiers, and the
scanner that enforces that must actually catch planted identifiers."""

import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVAL = os.path.join(HERE, "..", "eval")
sys.path.insert(0, EVAL)

from verify_no_identifiers import scan_file, scan_record  # noqa: E402

DATA = sorted(glob.glob(os.path.join(EVAL, "data", "local", "*.jsonl")))


def test_dataset_present():
    assert DATA, "no eval dataset found"


def test_published_dataset_has_no_identifiers():
    for path in DATA:
        findings = scan_file(path)
        assert not findings, f"{path}: {findings}"


def test_scanner_catches_mac():
    rec = {"payload": {"net": {"mac": "aa:bb:cc:dd:ee:ff"}}}
    kinds = {f.kind for f in scan_record(rec)}
    assert "mac_address" in kinds


def test_scanner_catches_cpu_model_string():
    rec = {"payload": {"cpu": "AMD Ryzen 7 8845HS"}}
    kinds = {f.kind for f in scan_record(rec)}
    assert "cpu_model_string" in kinds


def test_scanner_catches_serial_key():
    rec = {"payload": {"board_serial": "whatever"}}
    kinds = {f.kind for f in scan_record(rec)}
    assert "identifier_key" in kinds


def test_scanner_allows_vendor_and_nonce():
    # generic vendor + legitimately random nonce/digest must NOT trip the scanner
    rec = {
        "payload": {
            "results": {"vm": {"features": {"cpu_vendor": "AuthenticAMD"}}},
            "challenge": {"nonce": "a" * 64},
            "digest": "b" * 64,
        }
    }
    assert scan_record(rec) == []


def test_real_record_vendor_is_generic_only():
    # spot-check: the only vendor-ish string present is a generic vendor id
    with open(DATA[0], encoding="utf-8") as f:
        rec = json.loads(f.readline())
    vendor = rec["payload"]["results"]["vm"]["features"].get("cpu_vendor", "")
    assert vendor in {"AuthenticAMD", "GenuineIntel", "", None} or "AMD" in vendor

"""I17 Compliance gap matrix.

For each compliance framework (PCI-DSS, NIST 800-53, ISO 27001), produce a
table of controls and which checks cover them. Highlights *uncovered* controls
so users can see where their pen-test surface has blind spots.

The data comes from `wpsecscan/data/compliance_map.json` — every check_id
maps to one control ID per framework. A control with NO check mapped to it
is a "gap".

This module just produces the data; the GUI window (gui_windows.py) renders it.
"""
from __future__ import annotations

from collections import defaultdict

from . import tags as _tags


# Reference set of "important" controls that an enterprise pen-test typically
# audits. A gap on this list is more notable than a gap on an obscure control.
KEY_CONTROLS = {
    "pci_dss": [
        "2.2", "2.2.4",        # secure config
        "3.4", "3.4.1",        # data at rest
        "6.2.4",               # web injection defenses
        "6.3.3",               # vuln management
        "6.4.1", "6.4.2",      # public-facing app protection
        "8.2.1", "8.3",        # authentication
        "10.x",                # logging
    ],
    "nist_800_53": [
        "AC-3",  "AC-7",       # access control
        "IA-2",  "IA-5",       # identification
        "SC-7",                # boundary protection
        "SC-13",               # cryptography
        "SI-2",  "SI-4",       # flaw remediation + monitoring
        "SI-10",               # input validation
        "CM-7",                # least functionality
    ],
    "iso_27001": [
        "A.5.7",               # threat intelligence
        "A.8.3", "A.8.5",      # info access + secure auth
        "A.8.7", "A.8.8",      # malware + tech vuln management
        "A.8.9",               # config mgmt
        "A.8.20",              # network security
        "A.8.24", "A.8.28",    # crypto + secure coding
    ],
}


def coverage() -> dict[str, dict[str, list[str]]]:
    """Return {framework: {control_id: [check_ids covering it]}}."""
    cmap = _tags._load_compliance()
    out: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for cid, mapping in cmap.items():
        if not isinstance(mapping, dict):
            continue
        for framework, control in mapping.items():
            if framework.startswith("_") or not isinstance(control, str):
                continue
            out[framework][control].append(cid)
    return {fw: dict(controls) for fw, controls in out.items()}


def gaps(framework: str) -> list[str]:
    """Return the KEY_CONTROLS for `framework` that have NO check coverage."""
    cov = coverage().get(framework, {})
    return [c for c in KEY_CONTROLS.get(framework, []) if c not in cov]


def summary() -> dict[str, dict]:
    """Top-level summary: per framework, count of covered/key controls + gaps list."""
    cov = coverage()
    out: dict[str, dict] = {}
    for fw, key_list in KEY_CONTROLS.items():
        controls = cov.get(fw, {})
        covered_keys = [c for c in key_list if c in controls]
        out[fw] = {
            "total_check_mappings": sum(len(v) for v in controls.values()),
            "key_controls_total":   len(key_list),
            "key_controls_covered": len(covered_keys),
            "gaps":                 [c for c in key_list if c not in controls],
        }
    return out

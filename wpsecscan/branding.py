"""FEAT-050 — white-label branding config for HTML + executive-PDF reports.

Reads ~/.wpsecscan/brand.json. When present, reporters inject the
configured logo URL, primary colour, agency name, and footer text into
their output. The OSS build ships with a small `wpsecscan` watermark
in the HTML footer; setting `brand.json` removes the watermark and
substitutes the agency's identity.

Schema (all optional):
    {
        "agency_name":   "Smith Security Audits",
        "primary_color": "#1a73e8",
        "logo_url":      "https://example.com/logo.svg",
        "footer_text":   "© Smith Security Audits 2026. Confidential.",
        "client_name":   "Acme Corp"
    }
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def _brand_path() -> Path:
    return _home() / "brand.json"


def load_brand() -> dict:
    """Returns the brand config dict, or an empty dict when no file exists.

    Templates check for truthy fields and fall back to default WPSecScan
    branding when absent. Always-defensive against partial / malformed
    JSON so a bad brand.json doesn't break report generation.
    """
    p = _brand_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Filter to known keys to defend against template-injection via brand file.
    safe = {}
    for k in ("agency_name", "primary_color", "logo_url", "footer_text", "client_name"):
        v = data.get(k)
        if isinstance(v, str) and len(v) < 2000:
            safe[k] = v
    return safe

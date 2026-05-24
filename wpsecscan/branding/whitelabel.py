"""White-label branding for enterprise resellers.

Round-64 #119 — replace logo, organisation name, primary/accent colours,
and footer text via `~/.wpsecscan/brand.json`. Used by reports +
PDF exporter.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path

# Reuse the same shape as reporters/pdf_custom_branding.py so reports share the config.
from ..reporters.pdf_custom_branding import Branding, apply_to_pdf_styles  # noqa: F401


def write_branding(b: Branding) -> None:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    home.mkdir(parents=True, exist_ok=True)
    p = home / "brand.json"
    if p.is_symlink():
        p.unlink()
    p.write_text(json.dumps(asdict(b), indent=2), encoding="utf-8")


def reset_branding() -> None:
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    p = home / "brand.json"
    if p.exists():
        p.unlink()


@dataclass
class HtmlReportBrand:
    """Used by the HTML/dashboard reporters."""
    organization_name: str
    primary_color: str
    accent_color: str
    logo_data_url: str | None  # inline base64 to avoid asset paths

    @classmethod
    def from_branding(cls, b: Branding) -> "HtmlReportBrand":
        logo_data_url = None
        if b.logo_path:
            try:
                import base64
                data = Path(b.logo_path).read_bytes()
                mime = "image/png" if b.logo_path.lower().endswith(".png") else "image/svg+xml"
                logo_data_url = f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"
            except OSError:
                pass
        return cls(
            organization_name=b.organization_name,
            primary_color=b.primary_color,
            accent_color=b.accent_color,
            logo_data_url=logo_data_url,
        )

"""Voice-summary export.

Round-64 #102 — `--voice-summary <path.wav>` writes a spoken
executive summary to a WAV file via pyttsx3 (optional dep). When
pyttsx3 isn't installed, falls back to writing a .txt next to the
requested path.
"""
from __future__ import annotations

from pathlib import Path


def _build_summary(report: dict) -> str:
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    target = report.get("target", "your site") if isinstance(report, dict) else "your site"
    crit = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    med = int(summary.get("medium", 0))
    parts = [f"Security scan of {target}."]
    if crit + high == 0:
        parts.append("No critical or high-severity issues were found.")
    else:
        if crit:
            parts.append(f"Found {crit} critical issue{'s' if crit != 1 else ''}.")
        if high:
            parts.append(f"Found {high} high-severity issue{'s' if high != 1 else ''}.")
    if med:
        parts.append(f"Also found {med} medium-severity issue{'s' if med != 1 else ''}.")
    parts.append("Open the full report for remediation details.")
    return " ".join(parts)


def export_voice_summary(report: dict, out_path: str) -> str:
    """Write WAV; returns the actual file written.

    Falls back to .txt if pyttsx3 isn't installed.
    """
    text = _build_summary(report)
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink():
        p.unlink()
    try:
        import pyttsx3  # type: ignore
        engine = pyttsx3.init()
        engine.save_to_file(text, str(p))
        engine.runAndWait()
        return str(p)
    except (ImportError, RuntimeError, OSError):
        # Fallback: write the text alongside
        txt_path = p.with_suffix(".txt")
        if txt_path.is_symlink():
            txt_path.unlink()
        txt_path.write_text(text, encoding="utf-8")
        return str(txt_path)

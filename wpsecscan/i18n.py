"""E6 i18n stub — translation dictionaries for the GUI labels.

WordPress's most-used non-English language is Spanish, so we ship a starter
Spanish dictionary. Additional locales can be dropped into
~/.wpsecscan/locales/<code>.json as flat {key: translation} maps; they're
loaded at import time.

Usage:
    from . import i18n
    i18n.set_locale("es")          # switch
    label = i18n.t("scan")         # -> "Escanear"

Keys that aren't found in the active locale fall back to the English string.
"""
from __future__ import annotations

import json
from pathlib import Path

# English is the canonical key set — every other locale is a subset.
EN = {
    # Menus
    "file": "File",
    "tools": "Tools",
    "view": "View",
    "help": "Help",
    # Buttons
    "scan": "Scan",
    "cancel": "Cancel",
    "rescan": "Re-scan",
    "open_html": "Open HTML",
    "open_folder": "Open folder",
    "copy_json": "Copy JSON",
    "settings": "Settings...",
    "close": "Close",
    "save": "Save",
    "delete": "Delete",
    # Labels
    "url": "URL",
    "severity": "Severity",
    "title": "Title",
    "evidence": "Evidence",
    "remediation": "Remediation",
    "risk_score": "Risk score",
    # Status
    "scanning": "Scanning...",
    "done": "Done",
    "cancelled": "Cancelled",
    "no_findings": "No findings.",
    # Severities (already lowercase in models; ui_labels here)
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    # Tutorial
    "welcome_title": "Welcome to WPSecScan",
    "skip_tour": "Skip tour",
}

ES = {
    "file": "Archivo",
    "tools": "Herramientas",
    "view": "Ver",
    "help": "Ayuda",
    "scan": "Escanear",
    "cancel": "Cancelar",
    "rescan": "Re-escanear",
    "open_html": "Abrir HTML",
    "open_folder": "Abrir carpeta",
    "copy_json": "Copiar JSON",
    "settings": "Ajustes...",
    "close": "Cerrar",
    "save": "Guardar",
    "delete": "Eliminar",
    "url": "URL",
    "severity": "Severidad",
    "title": "Título",
    "evidence": "Evidencia",
    "remediation": "Remediación",
    "risk_score": "Puntuación de riesgo",
    "scanning": "Escaneando...",
    "done": "Listo",
    "cancelled": "Cancelado",
    "no_findings": "Sin hallazgos.",
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Bajo",
    "info": "Info",
    "welcome_title": "Bienvenido a WPSecScan",
    "skip_tour": "Saltar tour",
}

# Active locale map; built-ins + user-supplied overrides
_LOCALES: dict[str, dict[str, str]] = {"en": EN, "es": ES}

# Currently-selected locale (read by t())
_ACTIVE = "en"


def _load_user_locales() -> None:
    """Merge any user-supplied translation files from ~/.wpsecscan/locales/."""
    from .history import _home
    locales_dir = Path(_home()) / "locales"
    if not locales_dir.exists():
        return
    for f in locales_dir.glob("*.json"):
        code = f.stem.lower()
        try:
            data = json.loads(f.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        # Merge over any existing built-in; user file wins
        base = dict(_LOCALES.get(code) or {})
        base.update({k: str(v) for k, v in data.items() if isinstance(k, str)})
        _LOCALES[code] = base


_load_user_locales()


def available_locales() -> list[str]:
    return sorted(_LOCALES.keys())


def set_locale(code: str) -> None:
    """Switch active locale. Unknown codes fall back to English silently."""
    global _ACTIVE
    code = (code or "en").lower()
    _ACTIVE = code if code in _LOCALES else "en"


def get_locale() -> str:
    return _ACTIVE


def t(key: str) -> str:
    """Translate. Falls back to English, then to the raw key."""
    return _LOCALES.get(_ACTIVE, {}).get(key) or EN.get(key) or key

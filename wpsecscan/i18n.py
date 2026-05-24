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

# Round-59 #73 — built-in locales beyond en/es. We ship starter
# dictionaries for the languages with the largest non-English WordPress
# user-base: French, German, Portuguese-BR, Japanese, Chinese-zh-CN.
# Users override / extend by dropping ~/.wpsecscan/locales/<code>.json.
FR = {
    "file": "Fichier", "tools": "Outils", "view": "Affichage", "help": "Aide",
    "scan": "Analyser", "cancel": "Annuler", "rescan": "Ré-analyser",
    "open_html": "Ouvrir HTML", "open_folder": "Ouvrir dossier",
    "copy_json": "Copier JSON", "settings": "Paramètres...", "close": "Fermer",
    "save": "Enregistrer", "delete": "Supprimer", "url": "URL",
    "severity": "Sévérité", "title": "Titre", "evidence": "Preuve",
    "remediation": "Remédiation", "risk_score": "Score de risque",
    "scanning": "Analyse en cours...", "done": "Terminé", "cancelled": "Annulé",
    "no_findings": "Aucune trouvaille.",
    "critical": "Critique", "high": "Élevé", "medium": "Moyen", "low": "Faible", "info": "Info",
    "welcome_title": "Bienvenue dans WPSecScan", "skip_tour": "Passer le tour",
}
DE = {
    "file": "Datei", "tools": "Werkzeuge", "view": "Ansicht", "help": "Hilfe",
    "scan": "Scannen", "cancel": "Abbrechen", "rescan": "Erneut scannen",
    "open_html": "HTML öffnen", "open_folder": "Ordner öffnen",
    "copy_json": "JSON kopieren", "settings": "Einstellungen...", "close": "Schließen",
    "save": "Speichern", "delete": "Löschen", "url": "URL",
    "severity": "Schweregrad", "title": "Titel", "evidence": "Nachweis",
    "remediation": "Behebung", "risk_score": "Risikobewertung",
    "scanning": "Scanne...", "done": "Fertig", "cancelled": "Abgebrochen",
    "no_findings": "Keine Funde.",
    "critical": "Kritisch", "high": "Hoch", "medium": "Mittel", "low": "Niedrig", "info": "Info",
    "welcome_title": "Willkommen bei WPSecScan", "skip_tour": "Tour überspringen",
}
PT_BR = {
    "file": "Arquivo", "tools": "Ferramentas", "view": "Exibir", "help": "Ajuda",
    "scan": "Escanear", "cancel": "Cancelar", "rescan": "Reescanear",
    "open_html": "Abrir HTML", "open_folder": "Abrir pasta",
    "copy_json": "Copiar JSON", "settings": "Configurações...", "close": "Fechar",
    "save": "Salvar", "delete": "Excluir", "url": "URL",
    "severity": "Gravidade", "title": "Título", "evidence": "Evidência",
    "remediation": "Correção", "risk_score": "Pontuação de risco",
    "scanning": "Escaneando...", "done": "Concluído", "cancelled": "Cancelado",
    "no_findings": "Nenhuma constatação.",
    "critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "info": "Info",
    "welcome_title": "Bem-vindo ao WPSecScan", "skip_tour": "Pular tour",
}
JA = {
    "file": "ファイル", "tools": "ツール", "view": "表示", "help": "ヘルプ",
    "scan": "スキャン", "cancel": "キャンセル", "rescan": "再スキャン",
    "open_html": "HTMLを開く", "open_folder": "フォルダを開く",
    "copy_json": "JSONをコピー", "settings": "設定...", "close": "閉じる",
    "save": "保存", "delete": "削除", "url": "URL",
    "severity": "重大度", "title": "タイトル", "evidence": "証拠",
    "remediation": "修正方法", "risk_score": "リスクスコア",
    "scanning": "スキャン中...", "done": "完了", "cancelled": "キャンセルされました",
    "no_findings": "検出なし。",
    "critical": "重大", "high": "高", "medium": "中", "low": "低", "info": "情報",
    "welcome_title": "WPSecScanへようこそ", "skip_tour": "ツアーをスキップ",
}
ZH_CN = {
    "file": "文件", "tools": "工具", "view": "查看", "help": "帮助",
    "scan": "扫描", "cancel": "取消", "rescan": "重新扫描",
    "open_html": "打开HTML", "open_folder": "打开文件夹",
    "copy_json": "复制JSON", "settings": "设置...", "close": "关闭",
    "save": "保存", "delete": "删除", "url": "URL",
    "severity": "严重程度", "title": "标题", "evidence": "证据",
    "remediation": "修复建议", "risk_score": "风险评分",
    "scanning": "扫描中...", "done": "完成", "cancelled": "已取消",
    "no_findings": "无发现。",
    "critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息",
    "welcome_title": "欢迎使用 WPSecScan", "skip_tour": "跳过教程",
}

# Active locale map; built-ins + user-supplied overrides
_LOCALES: dict[str, dict[str, str]] = {
    "en": EN, "es": ES, "fr": FR, "de": DE, "pt-br": PT_BR, "ja": JA, "zh-cn": ZH_CN,
}

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

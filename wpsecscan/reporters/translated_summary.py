"""Translated executive summary (static phrases, 6 languages).

Round-64 #97 — produces a short executive summary translated into one
of: en, es, de, fr, ja, zh. Static phrases only — no machine
translation involved.
"""
from __future__ import annotations


_PHRASES = {
    "en": {
        "title":      "Security scan summary",
        "scanned":    "Scanned",
        "grade":      "Overall grade",
        "critical":   "Critical issues",
        "high":       "High issues",
        "medium":     "Medium issues",
        "low":        "Low issues",
        "info":       "Informational",
        "no_issues":  "No urgent issues detected",
        "action":     "Next steps: review findings; forward to your security or hosting team.",
    },
    "es": {
        "title":      "Resumen del análisis de seguridad",
        "scanned":    "Analizado",
        "grade":      "Calificación general",
        "critical":   "Problemas críticos",
        "high":       "Problemas altos",
        "medium":     "Problemas medios",
        "low":        "Problemas bajos",
        "info":       "Informativo",
        "no_issues":  "No se detectaron problemas urgentes",
        "action":     "Próximos pasos: revisa los hallazgos y reenvíalos a tu equipo de seguridad.",
    },
    "de": {
        "title":      "Sicherheitsscan-Zusammenfassung",
        "scanned":    "Gescannt",
        "grade":      "Gesamtnote",
        "critical":   "Kritische Probleme",
        "high":       "Hohe Probleme",
        "medium":     "Mittlere Probleme",
        "low":        "Geringe Probleme",
        "info":       "Informativ",
        "no_issues":  "Keine dringenden Probleme festgestellt",
        "action":     "Nächste Schritte: Befunde prüfen und an das Sicherheits-Team weiterleiten.",
    },
    "fr": {
        "title":      "Résumé de l'analyse de sécurité",
        "scanned":    "Analysé",
        "grade":      "Note globale",
        "critical":   "Problèmes critiques",
        "high":       "Problèmes élevés",
        "medium":     "Problèmes moyens",
        "low":        "Problèmes faibles",
        "info":       "Informatif",
        "no_issues":  "Aucun problème urgent détecté",
        "action":     "Étapes suivantes : examiner les résultats et les transmettre à votre équipe sécurité.",
    },
    "ja": {
        "title":      "セキュリティスキャン概要",
        "scanned":    "スキャン対象",
        "grade":      "総合評価",
        "critical":   "重大な問題",
        "high":       "高優先度の問題",
        "medium":     "中優先度の問題",
        "low":        "低優先度の問題",
        "info":       "参考情報",
        "no_issues":  "緊急の問題は検出されませんでした",
        "action":     "次のステップ: 結果を確認し、セキュリティチームに転送してください。",
    },
    "zh": {
        "title":      "安全扫描摘要",
        "scanned":    "已扫描",
        "grade":      "总体评级",
        "critical":   "严重问题",
        "high":       "高危问题",
        "medium":     "中危问题",
        "low":        "低危问题",
        "info":       "信息",
        "no_issues":  "未检测到紧急问题",
        "action":     "下一步: 查看结果并转发给安全团队.",
    },
}


def supported_languages() -> list[str]:
    return list(_PHRASES.keys())


def render_translated(target: str, summary: dict, lang: str = "en") -> str:
    p = _PHRASES.get(lang, _PHRASES["en"])
    crit = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    med = int(summary.get("medium", 0))
    low = int(summary.get("low", 0))
    info = int(summary.get("info", 0))
    grade = "F" if crit else "D" if high else "C" if med > 2 else "B" if med else "A"
    lines = [
        p["title"],
        "=" * len(p["title"]),
        "",
        f"{p['scanned']}: {target}",
        f"{p['grade']}: {grade}",
        "",
        f"{p['critical']}: {crit}",
        f"{p['high']}: {high}",
        f"{p['medium']}: {med}",
        f"{p['low']}: {low}",
        f"{p['info']}: {info}",
        "",
    ]
    if crit == 0 and high == 0:
        lines.append(p["no_issues"])
    else:
        lines.append(p["action"])
    return "\n".join(lines)

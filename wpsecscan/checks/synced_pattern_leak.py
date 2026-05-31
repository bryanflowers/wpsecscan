"""F9 (v2.8.1) — Synced-pattern (formerly Reusable Block) content leak.

WP 6.3+ exposes synced patterns at `/wp-json/wp/v2/blocks`. By
default this requires the `edit_posts` capability, but some sites
have it filtered open. Public exposure leaks unpublished/private
content (drafts in patterns, sensitive snippets, etc.).
"""
from __future__ import annotations

from ..http import Client
from ..models import Finding


async def check(client: Client, ctx: dict) -> list[Finding]:
    step = ctx.get("step") or (lambda _s: None)
    step("F9: probing /wp-json/wp/v2/blocks for synced-pattern leak")
    r = await client.get("/wp-json/wp/v2/blocks?per_page=1")
    if r is None:
        return []
    if r.status_code == 200:
        try:
            data = r.json()
        except ValueError:
            return []
        if isinstance(data, list) and data:
            return [Finding(severity="medium",
                              title=f"F9: /wp-json/wp/v2/blocks publicly returns {len(data)}+ synced patterns",
                              evidence=(
                                  "Public unauthenticated GET returned synced-pattern data. "
                                  "Patterns may contain unpublished content, internal "
                                  "snippets, or sensitive drafts."),
                              remediation=(
                                  "Add to functions.php: "
                                  "`add_filter('rest_pre_dispatch', function($r,$s,$req){"
                                  "if(strpos($req->get_route(),'/wp/v2/blocks')!==false "
                                  "&& !current_user_can('edit_posts')) return new "
                                  "WP_Error('rest_forbidden','',['status'=>401]); return $r;},10,3);`"),
                              url=ctx["target"])]
    return []

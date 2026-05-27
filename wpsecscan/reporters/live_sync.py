"""C51 (v2.7.0) — Confluence / Notion live page sync.

Pushes the agency dashboard (or any rendered HTML) to a Confluence
space or Notion database, refreshed on every scan. Different from the
existing one-shot export — this UPDATES the SAME page so the live URL
always reflects the most-recent scan.

Confluence: PUT /wiki/rest/api/content/{page_id} with the new body.
Notion:    PATCH /v1/blocks/{page_id}/children with replacement blocks.

Both backends are no-op when their env vars aren't set, so the
emitter can fire on every scan without breaking unconfigured installs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx


def sync_confluence(html_body: str, *, page_id: str | None = None,
                     base_url: str | None = None,
                     email: str | None = None) -> tuple[bool, str]:
    """Update a Confluence page's body with `html_body`. Returns
    (ok, message). Reads creds from env vars when args are None:

      WPSECSCAN_CONFLUENCE_BASE_URL   https://your.atlassian.net/wiki
      WPSECSCAN_CONFLUENCE_EMAIL      user@example.com
      WPSECSCAN_CONFLUENCE_TOKEN      Atlassian API token
      WPSECSCAN_CONFLUENCE_PAGE_ID    target page id
    """
    base = base_url or os.environ.get("WPSECSCAN_CONFLUENCE_BASE_URL", "")
    em   = email    or os.environ.get("WPSECSCAN_CONFLUENCE_EMAIL", "")
    pid  = page_id  or os.environ.get("WPSECSCAN_CONFLUENCE_PAGE_ID", "")
    tok  = os.environ.get("WPSECSCAN_CONFLUENCE_TOKEN", "")
    if not (base and em and pid and tok):
        return False, "confluence not configured (set WPSECSCAN_CONFLUENCE_* env vars)"
    import base64
    auth = base64.b64encode(f"{em}:{tok}".encode()).decode()
    try:
        with httpx.Client(timeout=20.0) as c:
            # Fetch current version (Confluence requires it for PUT)
            cur = c.get(f"{base.rstrip('/')}/rest/api/content/{pid}",
                         headers={"Authorization": f"Basic {auth}"})
            if cur.status_code != 200:
                return False, f"confluence GET {pid}: {cur.status_code}"
            current = cur.json()
            version = int((current.get("version") or {}).get("number", 0)) + 1
            r = c.put(
                f"{base.rstrip('/')}/rest/api/content/{pid}",
                headers={"Authorization": f"Basic {auth}",
                          "Content-Type": "application/json"},
                json={
                    "id": pid,
                    "type": "page",
                    "title": current.get("title", "WPSecScan dashboard"),
                    "version": {"number": version},
                    "body": {"storage": {"value": html_body, "representation": "storage"}},
                },
            )
            if r.status_code in (200, 204):
                return True, f"confluence page {pid} updated to v{version}"
            return False, f"confluence PUT {pid}: {r.status_code} {r.text[:200]}"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return False, f"confluence error: {e}"


def sync_notion(text_body: str, *, page_id: str | None = None) -> tuple[bool, str]:
    """Replace the children of a Notion page with a paragraph-block
    representation of `text_body` (Notion doesn't accept raw HTML;
    the caller should pre-render to plain text or markdown).

    Reads creds:
      WPSECSCAN_NOTION_TOKEN    Notion integration internal-integration token
      WPSECSCAN_NOTION_PAGE_ID  target page id
    """
    pid = page_id or os.environ.get("WPSECSCAN_NOTION_PAGE_ID", "")
    tok = os.environ.get("WPSECSCAN_NOTION_TOKEN", "")
    if not (pid and tok):
        return False, "notion not configured (set WPSECSCAN_NOTION_TOKEN + WPSECSCAN_NOTION_PAGE_ID)"
    headers = {
        "Authorization": f"Bearer {tok}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }
    # Notion paragraphs cap at ~2000 chars per text element; chunk.
    blocks = []
    for chunk in (text_body[i:i + 1800] for i in range(0, len(text_body), 1800)):
        blocks.append({
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{"type": "text", "text": {"content": chunk}}],
            },
        })
    try:
        with httpx.Client(timeout=20.0, headers=headers) as c:
            # Wipe existing children (Notion has no atomic replace, so we
            # delete-then-append). Get children first.
            r = c.get(f"https://api.notion.com/v1/blocks/{pid}/children")
            if r.status_code == 200:
                for child in r.json().get("results", [])[:100]:
                    cid = child.get("id")
                    if cid:
                        c.delete(f"https://api.notion.com/v1/blocks/{cid}")
            r = c.patch(
                f"https://api.notion.com/v1/blocks/{pid}/children",
                json={"children": blocks},
            )
            if r.status_code in (200, 201):
                return True, f"notion page {pid} updated ({len(blocks)} blocks)"
            return False, f"notion PATCH {pid}: {r.status_code} {r.text[:200]}"
    except (httpx.RequestError, httpx.HTTPStatusError) as e:
        return False, f"notion error: {e}"

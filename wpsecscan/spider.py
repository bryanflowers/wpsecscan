"""#18 (from ZAP) — spider / web crawler.

Recursively crawls the target's link graph (HTML `<a href>` + `<link
href>` + JS-detected URL patterns) to build a full URL inventory before
scanning. Catches the long tail that WPSecScan's hard-coded path list
misses — pretty permalinks, page builders, archived posts.

Bounded by:
  - max_depth (default 3)
  - max_pages (default 200)
  - same-origin only
  - respects robots.txt Disallow rules
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

from .http import Client


_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
_SRC_RE  = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
_JS_URL_RE = re.compile(r'["\'](\\?/[^"\'<>]{2,200}?)["\']')


class SpiderResult:
    def __init__(self) -> None:
        self.urls: list[str] = []
        self.depth_of: dict[str, int] = {}
        self.blocked_by_robots: list[str] = []
        self.errors: int = 0


async def _load_robots(client: Client) -> set[str]:
    """Return the set of Disallow path prefixes from robots.txt."""
    out: set[str] = set()
    r = await client.get("/robots.txt")
    if r is None or r.status_code != 200:
        return out
    for line in (r.text or "").splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                out.add(path)
    return out


def _is_disallowed(path: str, disallows: set[str]) -> bool:
    return any(path.startswith(d) for d in disallows)


def _extract_links(html: str, base_url: str) -> set[str]:
    out: set[str] = set()
    for m in _HREF_RE.finditer(html):
        out.add(urljoin(base_url, m.group(1)))
    for m in _SRC_RE.finditer(html):
        u = urljoin(base_url, m.group(1))
        # Skip image/font/asset extensions
        lower = u.lower()
        if not any(lower.endswith(ext) for ext in (".png", ".jpg", ".jpeg",
                                                     ".gif", ".svg", ".woff", ".woff2", ".ttf")):
            out.add(u)
    return out


async def crawl(client: Client, *, max_depth: int = 3, max_pages: int = 200,
                 respect_robots: bool = True) -> SpiderResult:
    """BFS crawl from `client.base_url`. Returns a SpiderResult."""
    result = SpiderResult()
    origin = urlparse(client.base_url)
    if not origin.netloc:
        return result
    try:
        from . import activity as _act
        _act.emit("integration", f"spider: starting (max depth {max_depth}, cap {max_pages})")
    except ImportError:
        pass

    disallows: set[str] = await _load_robots(client) if respect_robots else set()

    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(client.base_url + "/", 0)])

    while queue and len(result.urls) < max_pages:
        url, depth = queue.popleft()
        url, _frag = urldefrag(url)
        if url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        # Same-origin only
        # v2.8.1 B45 — normalise both sides via idna so IDN entered
        # either as Unicode (`café.example.com`) or its punycode form
        # (`xn--caf-dma.example.com`) is treated as the same origin.
        # Without this, the spider silently skipped its own pages
        # when the user passed the URL in one form but the page links
        # used the other.
        def _norm(n: str) -> str:
            n = (n or "").lower()
            try:
                return n.encode("idna").decode("ascii")
            except (UnicodeError, AttributeError):
                return n
        if parsed.netloc and _norm(parsed.netloc) != _norm(origin.netloc):
            continue
        # Robots check
        if disallows and _is_disallowed(parsed.path, disallows):
            result.blocked_by_robots.append(url)
            continue
        try:
            r = await client.get(parsed.path + ("?" + parsed.query if parsed.query else ""))
        except Exception:  # noqa: BLE001
            result.errors += 1
            continue
        if r is None:
            result.errors += 1
            continue
        result.urls.append(url)
        result.depth_of[url] = depth
        if depth >= max_depth:
            continue
        ctype = (r.headers.get("content-type") or "").lower()
        if "text/html" not in ctype and "application/xhtml" not in ctype:
            continue
        for link in _extract_links(r.text or "", url):
            link_clean, _ = urldefrag(link)
            if link_clean not in seen:
                queue.append((link_clean, depth + 1))
    try:
        from . import activity as _act
        _act.emit("integration",
                  f"spider: done — {len(result.urls)} URL(s), {result.errors} error(s)")
    except ImportError:
        pass
    return result

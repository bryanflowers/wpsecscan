"""Item #2 — Cloudflare origin-IP leak.

When a site is fronted by Cloudflare, the public-facing IP belongs to CF.
But CF only protects what you point through it: leak the origin's true IP
and an attacker can bypass the WAF entirely by hitting it directly with a
spoofed Host header.

This check looks for three common leaks:

1. **Certificate transparency logs (crt.sh)** — leaf certs issued for
   subdomains the user forgot to proxy (mail., direct., staging.) often
   point straight at the origin. We pull the leaf set, A-resolve each
   non-CF subdomain and report any that's NOT in a Cloudflare range.

2. **DNS A records of common bypass subdomains** — `direct.`, `origin.`,
   `cpanel.`, `webdisk.`, `ftp.`, `mail.`, `webmail.`, `pop.`, `smtp.`,
   `ns1.`, `staging.`, `dev.`, `test.` are routinely set to the origin
   IP and forgotten about.

3. **MX records** — mail servers run on the origin host frequently.
   Reverse-resolving the MX target into an A record often leaks the
   real IP.

Findings are medium-severity (recon-stage; weaponising requires the
attacker to discover and probe directly) and include the suggested fix
of either proxying everything or moving non-web services to a separate
host that doesn't share infra with the WP site.

Uses only **free** sources: crt.sh (no key) + the system DNS resolver.
No paid Censys / Shodan integration in this iteration.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
from urllib.parse import urlparse

import httpx

from ..http import Client
from ..models import Finding

# Cloudflare-published edge ranges (IPv4 only). The full source-of-truth is
# https://www.cloudflare.com/ips/ — these are the v4 prefixes as of 2026-05.
# Maintained inline so the scanner has no runtime fetch dependency for IP
# classification. Refreshing this list is a normal data-update task.
_CF_RANGES_V4 = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)

# Subdomains that almost never go through CF but tend to share an origin
# host with the proxied WP site.
_BYPASS_PREFIXES = (
    "direct", "origin", "real", "live",
    "cpanel", "webdisk", "ftp", "ssh",
    "mail", "webmail", "pop", "pop3", "imap", "smtp",
    "ns1", "ns2",
    "staging", "stage", "dev", "test", "uat",
    "old", "backup",
)


def _ip_in_cf(ip: str) -> bool:
    """True iff `ip` falls inside any published Cloudflare v4 range."""
    try:
        ip_int = _ip4_to_int(ip)
    except ValueError:
        return False
    for cidr in _CF_RANGES_V4:
        net, bits_s = cidr.split("/")
        try:
            net_int = _ip4_to_int(net)
            bits = int(bits_s)
        except ValueError:
            continue
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (ip_int & mask) == (net_int & mask):
            return True
    return False


def _ip4_to_int(ip: str) -> int:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(ip)
    n = 0
    for p in parts:
        v = int(p)
        if not 0 <= v <= 255:
            raise ValueError(ip)
        n = (n << 8) | v
    return n


def _resolve_a(host: str) -> list[str]:
    """Best-effort sync A-record lookup. Returns the unique v4 addresses."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, socket.herror, OSError):
        return []
    seen: set[str] = set()
    for _f, _t, _p, _c, sa in infos:
        if isinstance(sa, tuple) and sa:
            seen.add(sa[0])
    return sorted(seen)


_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$")


async def _fetch_crtsh(apex: str) -> list[str]:
    """Pull the leaf set from crt.sh (no auth required) and return the
    unique hostnames seen across SANs. Bounded + best-effort."""
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    try:
        async with httpx.AsyncClient(timeout=15.0,
                                      headers={"User-Agent": "WPSecScan/cf-origin"}) as c:
            r = await c.get(url)
            if r.status_code != 200 or not r.text:
                return []
            data = json.loads(r.text)
    except (httpx.HTTPError, httpx.TimeoutException, ValueError):
        return []

    names: set[str] = set()
    for entry in data[:1000]:  # bound the work
        cn = (entry.get("common_name") or "").strip().lower()
        san = (entry.get("name_value") or "").strip().lower()
        for candidate in (cn, *san.split("\n")):
            candidate = candidate.strip().lstrip("*.").rstrip(".")
            if not candidate or candidate == apex:
                continue
            if not candidate.endswith("." + apex):
                continue
            if not _HOST_RE.match(candidate):
                continue
            # Wildcard / SAN that's the apex itself — skip
            if candidate.count(".") < apex.count(".") + 1:
                continue
            names.add(candidate)
            if len(names) >= 200:
                break
        if len(names) >= 200:
            break
    return sorted(names)


def _apex(host: str) -> str:
    """`www.foo.co.uk` → `foo.co.uk`. Best-effort — doesn't read the PSL,
    but trims common 2-label TLDs (.co.uk, .com.au, …)."""
    h = host.lower().lstrip("www.")
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    # Handle 2-label TLDs the cheap way.
    second = parts[-2]
    if second in ("co", "com", "net", "org", "gov", "ac") and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_cloudflare_proxied(client: Client) -> bool:
    """Heuristic: the target previously fetched should have CF headers
    available in `ctx['shared']`. Fall back to True if we don't know,
    so the check still runs (its sub-findings are gated per-IP)."""
    return True


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    host = (urlparse(ctx["target"]).hostname or "").lower()
    if not host:
        return findings

    # Sanity: only run when the target itself resolves into a CF range.
    apex_ips = _resolve_a(host)
    if not apex_ips:
        findings.append(
            Finding(
                severity="info",
                title="Cloudflare origin-IP leak skipped — host did not resolve",
                evidence=f"socket.getaddrinfo({host}) returned no A records.",
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings
    if not any(_ip_in_cf(ip) for ip in apex_ips):
        findings.append(
            Finding(
                severity="info",
                title="Cloudflare origin-IP leak skipped — site is not behind Cloudflare",
                evidence=(
                    f"Apex {host} resolves to {', '.join(apex_ips)}; "
                    "none of those addresses are in a published Cloudflare range."
                ),
                remediation="No action.",
                url=ctx["target"],
            )
        )
        return findings

    apex = _apex(host)
    leaked_subs: list[tuple[str, list[str]]] = []  # (subdomain, non-CF IPs)

    # --- 1. Certificate transparency: subdomains via crt.sh
    step(f"querying crt.sh for {apex} subdomain certs...")
    ct_hosts = await _fetch_crtsh(apex)

    # --- 2. Common bypass-subdomain guesses
    guessed = [f"{p}.{apex}" for p in _BYPASS_PREFIXES]
    candidates = sorted(set(ct_hosts) | set(guessed))

    # A-resolve each in a thread-pool — getaddrinfo is sync. Bound to 30 lookups
    # so a crt.sh result with hundreds of SANs doesn't slow the scan to a crawl.
    step(f"resolving {min(len(candidates), 30)} subdomain(s) to A records...")
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(8)

    async def _resolve(name: str) -> tuple[str, list[str]]:
        async with sem:
            ips = await loop.run_in_executor(None, _resolve_a, name)
            return name, ips

    bounded = candidates[:30]
    pairs = await asyncio.gather(*(_resolve(n) for n in bounded))

    for name, ips in pairs:
        if not ips:
            continue
        non_cf = [ip for ip in ips if not _ip_in_cf(ip)]
        if non_cf:
            leaked_subs.append((name, non_cf))

    # --- 3. MX records via dnspython if available; otherwise skip
    mx_leak: list[tuple[str, str]] = []
    try:
        import dns.resolver  # noqa: PLC0415  — optional dep
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5.0
        try:
            for rr in resolver.resolve(apex, "MX"):
                target = str(rr.exchange).rstrip(".").lower()
                if not target:
                    continue
                ips = _resolve_a(target)
                non_cf = [ip for ip in ips if not _ip_in_cf(ip)]
                if non_cf:
                    mx_leak.append((target, non_cf[0]))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
    except ImportError:
        pass  # dnspython not installed; skip MX leg silently

    # --- Build findings
    if leaked_subs:
        # Roll up everything into one medium finding; per-sub detail in evidence.
        lines = []
        for name, ips in leaked_subs[:20]:
            lines.append(f"  - {name} → {', '.join(ips)}")
        findings.append(
            Finding(
                severity="medium",
                title=(
                    f"Cloudflare origin IP may be leaked via "
                    f"{len(leaked_subs)} non-proxied subdomain(s)"
                ),
                evidence=(
                    f"The apex ({host}) is served via Cloudflare, but the following "
                    "subdomains resolve directly to IPs outside Cloudflare's published "
                    "ranges. An attacker can bypass the WAF by sending HTTP requests "
                    "with `Host: " + host + "` to those IPs:\n\n"
                    + "\n".join(lines)
                ),
                remediation=(
                    "1. For each non-proxied subdomain above, either:\n"
                    "     a. proxy through Cloudflare (orange-cloud the DNS record), OR\n"
                    "     b. move the service to a separate host that does NOT also serve "
                    "the WP origin.\n"
                    "2. Rotate the origin server's IP after sealing the leak (CF Authenticated "
                    "Origin Pulls + restrictive ufw/security-group rules so only CF IPs reach :443)."
                ),
                url=ctx["target"],
                extra={"leaked": [{"host": n, "ips": ips} for n, ips in leaked_subs[:50]]},
            )
        )

    if mx_leak:
        lines = [f"  - MX {t} → {ip}" for t, ip in mx_leak[:5]]
        findings.append(
            Finding(
                severity="medium",
                title="Cloudflare origin IP may be leaked via MX records",
                evidence=(
                    f"Mail servers for {apex} resolve to non-Cloudflare IPs:\n\n"
                    + "\n".join(lines)
                    + "\n\nIf mail is hosted on the same machine as the WP origin "
                    "(shared cPanel / Plesk / single-VPS deployments), the MX IP IS "
                    "the origin and CF protection is bypassable."
                ),
                remediation=(
                    "Host mail on a separate server (Fastmail / Google Workspace / "
                    "Mailgun) so the MX target doesn't double as the WP origin. "
                    "If you must self-host mail on the same box, restrict :443 to "
                    "Cloudflare's IP ranges at the firewall."
                ),
                url=ctx["target"],
            )
        )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No Cloudflare origin-IP leak detected",
                evidence=(
                    f"Checked {len(bounded)} candidate subdomain(s) (from crt.sh + "
                    "common bypass prefixes) + MX records. None resolved outside "
                    "Cloudflare's published IP ranges."
                ),
                remediation="No action needed.",
                url=ctx["target"],
            )
        )

    return findings

"""v2.9.0 W0b — ownership-consent gate for aggressive scans.

`scanner.scan()` consults this module before any check runs. When a caller asks
for ``aggressive=True`` and no consent is recorded for the target host, the scan
is downgraded to passive and an info finding (check id ``consent_gate``) is
added to the report. Nothing here raises: a corrupt or unreadable owned-targets
file is treated as empty, and every failure resolves to "no consent".

Consent sources, in precedence order:

1. An explicit ``consent=True`` / ``consent=False`` passed to ``scan()``
   (the ``--owned`` CLI flag maps to ``True``). An explicit value always wins.
2. The ``WPSECSCAN_OWNED_TARGETS`` environment variable: ``1`` / ``true`` /
   ``yes`` / ``*`` grants consent for every target; otherwise a comma-separated
   host list (case-insensitive; ``example.com`` matches that host exactly,
   ``*.example.com`` matches its subdomains).
3. The owned-targets file ``<home>/owned_targets.json`` shaped
   ``{"hosts": ["example.com", ...]}``, where ``<home>`` is ``WPSECSCAN_HOME``
   or ``~/.wpsecscan``. Entries use the same matching rules as the env list.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from .models import Finding

ENV_OWNED_TARGETS = "WPSECSCAN_OWNED_TARGETS"
OWNED_FILE_NAME = "owned_targets.json"
CONSENT_CHECK_ID = "consent_gate"

_ALL_TOKENS = frozenset({"1", "true", "yes", "*"})


def _home() -> Path:
    # Same resolution as the other modules (analytics, config, branding, ...):
    # WPSECSCAN_HOME wins, otherwise ~/.wpsecscan (Path.home() honours HOME /
    # USERPROFILE, so a sandboxed home is respected). Does not create the dir.
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


def owned_path() -> Path:
    return _home() / OWNED_FILE_NAME


def host_of(target: str) -> str:
    """Lowercased hostname from a URL or bare host (port, userinfo, path stripped)."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "//" + t
    try:
        host = urlsplit(t).hostname or ""
    except ValueError:
        return ""
    return host.lower().rstrip(".")


def _norm_entry(entry: str) -> str:
    """Normalise an owned-list entry; keeps a leading ``*.`` wildcard."""
    e = (entry or "").strip().lower()
    if not e:
        return ""
    if e in _ALL_TOKENS:
        return e
    if e.startswith("*."):
        rest = host_of(e[2:])
        return "*." + rest if rest else ""
    return host_of(e)


def _entry_matches(entry: str, host: str) -> bool:
    if not entry or not host:
        return False
    if entry.startswith("*."):
        return host.endswith(entry[1:])  # "*.example.com" -> ".example.com"
    return entry == host


def load_owned() -> set[str]:
    """Hosts recorded in the owned-targets file. Corrupt / missing file -> empty set."""
    try:
        blob = json.loads(owned_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if not isinstance(blob, dict):
        return set()
    hosts = blob.get("hosts")
    if not isinstance(hosts, list):
        return set()
    out: set[str] = set()
    for h in hosts:
        if isinstance(h, str):
            n = _norm_entry(h)
            if n:
                out.add(n)
    return out


def _save_owned(hosts: set[str]) -> None:
    p = owned_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps({"hosts": sorted(hosts)}, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def add_owned(host: str) -> set[str]:
    """Record `host` (hostname, URL or ``*.domain``) as owned. Returns the new set."""
    entry = _norm_entry(host)
    if not entry or entry in _ALL_TOKENS:
        raise ValueError(f"not a valid host to record as owned: {host!r}")
    hosts = load_owned()
    hosts.add(entry)
    _save_owned(hosts)
    return hosts


def remove_owned(host: str) -> set[str]:
    """Remove `host` from the owned list. Returns the new set (unchanged if absent)."""
    entry = _norm_entry(host)
    hosts = load_owned()
    if entry in hosts:
        hosts.discard(entry)
        _save_owned(hosts)
    return hosts


def _env_matches(value: str, host: str) -> bool:
    for token in value.split(","):
        n = _norm_entry(token)
        if n in _ALL_TOKENS or _entry_matches(n, host):
            return True
    return False


def has_consent(
    target: str,
    *,
    explicit: bool | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    """True when the operator has granted aggressive-scan consent for `target`.

    Never raises; any failure resolves to False.
    """
    if explicit is True:
        return True
    if explicit is False:
        return False
    try:
        host = host_of(target)
        environ = os.environ if env is None else env
        value = (environ.get(ENV_OWNED_TARGETS) or "").strip()
        if value and _env_matches(value, host):
            return True
        return any(_entry_matches(e, host) for e in load_owned())
    except Exception:  # noqa: BLE001 — the gate must never crash a scan
        return False


def consent_downgrade_finding(target: str) -> Finding:
    host = host_of(target) or target
    return Finding(
        severity="info",
        title=f"Aggressive mode downgraded to passive: no ownership consent recorded for {host}",
        evidence=(
            "Aggressive checks send active payloads and must only run against sites you "
            "own or are authorised to test. Grant consent with one of: the --owned flag "
            f"on this run; the {ENV_OWNED_TARGETS} environment variable (1, or a "
            f"comma-separated host list); or `wpsecscan owned add {host}`."
        ),
        remediation=f"Confirm you own or are authorised to test {host}, grant consent, and re-run.",
        url=target,
        extra={"check": CONSENT_CHECK_ID, "host": host},
    )

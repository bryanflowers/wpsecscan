"""#13 (from nuclei) — DNS template support (subset).

nuclei templates can include `dns:` blocks alongside `http:`. We add
a minimal DNS template runner that supports:

  - record types: A, AAAA, MX, TXT, NS, CNAME
  - matchers: word, regex (against the joined record values)
  - the "{{Host}}" variable substituted with the target's hostname

Templates in `~/.wpsecscan/templates/*.yaml` may include a `dns:` block:

    dns:
      - name: "{{Host}}"
        type: TXT
        matchers:
          - type: word
            words: ["v=spf1"]

Uses Python stdlib's socket + a manual DNS-query implementation for TXT/MX
to avoid taking on dnspython as a hard dep. For A / AAAA we use
socket.getaddrinfo. CNAME / NS / TXT / MX use a tiny built-in resolver.
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
from urllib.parse import urlparse

from ..http import Client
from ..models import Finding


def _build_dns_query(qname: str, qtype: int, qid: int = 0x1234) -> bytes:
    parts = [bytes([len(p)]) + p.encode("ascii") for p in qname.split(".") if p]
    name = b"".join(parts) + b"\x00"
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = name + struct.pack(">HH", qtype, 1)  # type, class IN
    return header + question


def _parse_dns_response(data: bytes, qtype: int) -> list[str]:
    """Tiny + tolerant DNS parser. Returns string-form records for A/AAAA/TXT/MX/NS/CNAME."""
    out: list[str] = []
    try:
        _qid, _flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        # Skip the question section
        idx = 12
        for _ in range(qdcount):
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 5  # null + type(2) + class(2)
        # Walk answer section
        for _ in range(ancount):
            # name pointer (2 bytes) — could be compressed, just skip
            if data[idx] & 0xC0:
                idx += 2
            else:
                while data[idx] != 0:
                    idx += data[idx] + 1
                idx += 1
            atype, _aclass, _attl, rdlen = struct.unpack(">HHIH", data[idx:idx + 10])
            idx += 10
            rdata = data[idx:idx + rdlen]
            if atype != qtype:
                idx += rdlen
                continue
            if atype == 1:  # A
                out.append(".".join(str(b) for b in rdata))
            elif atype == 28:  # AAAA
                out.append(":".join(f"{x:x}" for x in struct.unpack(">8H", rdata)))
            elif atype == 16:  # TXT
                txt_parts: list[str] = []
                i = 0
                while i < len(rdata):
                    l = rdata[i]
                    txt_parts.append(rdata[i + 1:i + 1 + l].decode("utf-8", errors="replace"))
                    i += 1 + l
                out.append("".join(txt_parts))
            elif atype in (2, 5):  # NS / CNAME — approximate decode
                out.append(rdata.decode("ascii", errors="replace").strip("\x00"))
            elif atype == 15:  # MX (prio + name)
                if len(rdata) >= 3:
                    prio = struct.unpack(">H", rdata[:2])[0]
                    name = rdata[2:].decode("ascii", errors="replace").strip("\x00")
                    out.append(f"{prio} {name}")
            idx += rdlen
    except (struct.error, IndexError, UnicodeDecodeError):
        pass
    return out


_QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def _resolve(qname: str, qtype: str, server: str = "1.1.1.1", timeout: float = 4.0) -> list[str]:
    t = _QTYPE.get(qtype.upper())
    if not t:
        return []
    if t in (1, 28):  # use stdlib for A/AAAA (handles search domains, /etc/hosts)
        try:
            family = socket.AF_INET if t == 1 else socket.AF_INET6
            return list({a[4][0] for a in socket.getaddrinfo(qname, None, family)})
        except (socket.gaierror, OSError):
            return []
    # Send raw UDP query for the rest
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_build_dns_query(qname, t), (server, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return _parse_dns_response(data, t)
    except (socket.timeout, OSError):
        return []


async def _run_dns_template(template: dict, ctx: dict) -> list[Finding]:
    info = template.get("info") or {}
    name = info.get("name") or template.get("id", "unnamed")
    sev_raw = (info.get("severity") or "info").lower()
    sev = {"critical": "critical", "high": "high", "medium": "medium",
           "low": "low", "info": "info"}.get(sev_raw, "info")

    host = urlparse(ctx["target"]).hostname or ctx["target"]
    findings: list[Finding] = []
    for dns_block in (template.get("dns") or []):
        qname = (dns_block.get("name") or "{{Host}}").replace("{{Host}}", host)
        qtype = (dns_block.get("type") or "A").upper()
        records = await asyncio.to_thread(_resolve, qname, qtype)
        haystack = "\n".join(records)
        matched = False
        for m in dns_block.get("matchers") or []:
            mtype = (m.get("type") or "").lower()
            if mtype == "word":
                words = m.get("words", []) or []
                cond = (m.get("condition") or "or").lower()
                hit = all(w in haystack for w in words) if cond == "and" \
                      else any(w in haystack for w in words)
                if hit:
                    matched = True
                    break
            elif mtype == "regex":
                pats = m.get("regex", []) or []
                for p in pats:
                    try:
                        if re.search(p, haystack):
                            matched = True
                            break
                    except re.error:
                        continue
                if matched:
                    break
        if matched:
            findings.append(Finding(
                severity=sev,
                title=f"[DNS template] {name}",
                evidence=f"Query {qtype} {qname} matched template '{template.get('id', '?')}'.\nRecords:\n  "
                        + "\n  ".join(records[:10]),
                remediation=info.get("description") or "See template for context.",
                url=ctx["target"],
                extra={"records": records, "template_id": template.get("id")},
            ))
            break
    return findings


async def check(client: Client, ctx: dict) -> list[Finding]:
    """Discovers + runs every DNS-block-bearing template."""
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)
    from .. import template_engine as _te
    if not _te._has_yaml():
        return [Finding(severity="info", title="DNS templates skipped (PyYAML not installed)",
                        evidence="Install pyyaml to enable.", remediation="No action.",
                        url=ctx["target"])]
    templates = _te.list_templates()
    dns_templates = []
    for p in templates:
        t = _te._load_template(p)
        if t and (t.get("dns") or []):
            dns_templates.append(t)
    if not dns_templates:
        findings.append(Finding(severity="info",
                                title="DNS templates — none in ~/.wpsecscan/templates/",
                                evidence="No template included a `dns:` block.",
                                remediation="No action.", url=ctx["target"]))
        return findings
    step(f"running {len(dns_templates)} DNS template(s)...")
    for t in dns_templates:
        try:
            findings.extend(await _run_dns_template(t, ctx))
        except Exception:  # noqa: BLE001
            continue
    return findings

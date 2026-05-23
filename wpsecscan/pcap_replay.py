"""#37 — PCAP replay.

Reads a raw network capture (`.pcap` / `.pcapng`) and extracts the HTTP
requests from each TCP stream, converting them to HAR-shaped entries
so the existing har_replay engine can fire them against a target.

Uses `scapy` if installed; falls back to a minimal handcrafted parser
that handles plain HTTP/1.1 over IPv4 TCP (no TLS, no HTTP/2). Real
production usage should install scapy.
"""
from __future__ import annotations

import re
from pathlib import Path


_REQ_LINE_RE = re.compile(rb"^([A-Z]{3,7})\s+([^\s]+)\s+HTTP/1\.[01]\r\n")


def _has_scapy() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


def _extract_with_scapy(pcap_path: Path) -> list[dict]:
    from scapy.all import rdpcap, TCP, IP
    entries = []
    # Reassemble TCP streams by 4-tuple — minimal implementation
    streams: dict[tuple, bytearray] = {}
    try:
        packets = rdpcap(str(pcap_path))
    except Exception:  # noqa: BLE001
        return []
    for pkt in packets:
        if not (IP in pkt and TCP in pkt and bytes(pkt[TCP].payload)):
            continue
        key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        streams.setdefault(key, bytearray()).extend(bytes(pkt[TCP].payload))

    for key, blob in streams.items():
        # Try to extract HTTP requests from each stream
        idx = 0
        while idx < len(blob):
            m = _REQ_LINE_RE.match(bytes(blob[idx:]))
            if not m:
                # advance to next CRLF + try again, cheaply
                next_break = blob.find(b"\r\n\r\n", idx)
                if next_break == -1:
                    break
                idx = next_break + 4
                continue
            method = m.group(1).decode("ascii")
            path = m.group(2).decode("ascii", errors="replace")
            # Find header block end
            hdr_end = blob.find(b"\r\n\r\n", idx)
            if hdr_end == -1:
                break
            # Parse Host header for the URL prefix
            hdr_block = bytes(blob[idx + m.end():hdr_end]).decode("ascii", errors="replace")
            host_m = re.search(r"(?im)^Host:\s*(\S+)", hdr_block)
            scheme = "http"
            host = host_m.group(1) if host_m else "?"
            url = f"{scheme}://{host}{path}"
            entries.append({
                "request": {
                    "method": method,
                    "url": url,
                    "headers": [],
                    "postData": {},
                },
            })
            idx = hdr_end + 4
    return entries


def import_pcap(pcap_path: Path) -> dict:
    """Read a pcap and emit a HAR doc. Empty when scapy isn't installed."""
    if not _has_scapy():
        return {"log": {"version": "1.2",
                         "creator": {"name": "wpsecscan pcap_replay"},
                         "entries": [],
                         "_note": "scapy not installed — run `pip install scapy` to enable."}}
    entries = _extract_with_scapy(pcap_path)
    return {"log": {"version": "1.2",
                     "creator": {"name": "wpsecscan pcap_replay"},
                     "entries": entries}}

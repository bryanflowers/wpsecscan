"""WPSecScan Python SDK — Round-64 #141.

Thin httpx wrapper around the daemon REST API.

Example:
    >>> from wpsecscan_client import WPSecScanClient
    >>> c = WPSecScanClient("http://localhost:8080", token="...")
    >>> scan_id = c.start_scan("https://example.com")
    >>> report = c.get_scan(scan_id, wait=True)
    >>> print(report["summary"])
"""
from __future__ import annotations

import time
from typing import Any

import httpx


__version__ = "2.2.0"


class WPSecScanClient:
    def __init__(self, base_url: str, *, token: str | None = None, timeout: float = 30.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "WPSecScanClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ---- scans ----
    def start_scan(self, target: str, *, aggressive: bool = False) -> str:
        r = self._client.post(
            f"{self.base_url}/scans",
            headers=self._headers,
            json={"target": target, "aggressive": aggressive},
        )
        r.raise_for_status()
        return r.json()["scan_id"]

    def get_scan(self, scan_id: str, *, wait: bool = False, poll_seconds: int = 5, timeout: int = 600) -> dict[str, Any]:
        if not wait:
            r = self._client.get(f"{self.base_url}/scans/{scan_id}", headers=self._headers)
            r.raise_for_status()
            return r.json()
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self._client.get(f"{self.base_url}/scans/{scan_id}", headers=self._headers)
            r.raise_for_status()
            data = r.json()
            if data.get("status") in ("complete", "failed"):
                return data
            time.sleep(poll_seconds)
        raise TimeoutError(f"Scan {scan_id} did not complete within {timeout}s")

    def list_scans(self, *, limit: int = 50) -> list[dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/scans", params={"limit": limit}, headers=self._headers)
        r.raise_for_status()
        return r.json().get("scans", [])

    # ---- sites ----
    def list_sites(self) -> list[dict[str, Any]]:
        r = self._client.get(f"{self.base_url}/sites", headers=self._headers)
        r.raise_for_status()
        return r.json().get("sites", [])

    def add_site(self, name: str, url: str, **kwargs) -> dict[str, Any]:
        body = {"name": name, "url": url, **kwargs}
        r = self._client.post(f"{self.base_url}/sites", json=body, headers=self._headers)
        r.raise_for_status()
        return r.json()

    # ---- findings ----
    def get_findings(self, scan_id: str, *, severity: str | None = None) -> list[dict[str, Any]]:
        params = {"severity": severity} if severity else None
        r = self._client.get(f"{self.base_url}/scans/{scan_id}/findings", params=params, headers=self._headers)
        r.raise_for_status()
        return r.json().get("findings", [])


__all__ = ["WPSecScanClient", "__version__"]

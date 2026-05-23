"""Payload Tester window â€” opens as a Toplevel from gui.py's Tools menu.

Single-shot: one Send button click = one HTTP request via wpsecscan.http.Client.
High-risk payloads (e.g. AWS metadata SSRF) require a confirm dialog before send.
Result can be saved as a finding into the main app's current report.
"""
from __future__ import annotations

import asyncio
import queue
import threading
import time
import tkinter as tk
from tkinter import StringVar, END, NORMAL, DISABLED, messagebox, ttk
from urllib.parse import urlparse

import ipaddress

import httpx

from .models import Finding


def _validate_target_url(url: str) -> tuple[bool, str]:
    """Reject targets that aren't http(s) to a real hostname.

    Rules:
      - must be http:// or https://
      - hostname required
      - no raw IP (specifically: don't let the payload tester probe AWS
        metadata at 169.254.169.254, the loopback at 127.0.0.1 etc.)
      - no file://, no ftp://, no localhost literal
    """
    if not url:
        return False, "no URL"
    try:
        p = urlparse(url)
    except (ValueError, TypeError):
        return False, "URL doesn't parse"
    if p.scheme not in ("http", "https"):
        return False, f"scheme must be http(s), got {p.scheme!r}"
    if not p.hostname:
        return False, "URL has no hostname"
    host = p.hostname.lower()
    if host == "localhost":
        return False, "loopback target rejected; use the host's real name"
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback or addr.is_link_local or addr.is_private or addr.is_multicast:
            return False, "private/loopback/link-local IP rejected"
        # Raw IP (even if public) — be conservative; the tester is meant for sites you own,
        # which generally have hostnames.
        return False, "use a hostname, not a raw IP"
    except ValueError:
        # Not an IP; that's the happy path.
        pass
    return True, ""
from .payloads import (
    Payload,
    VALID_CATEGORIES,
    by_category,
    evaluate_response,
    load_payloads,
)
from .prove import build_replay_curl


def _make_readonly(text_widget) -> None:
    """Bind a Text widget so it's read-only but keyboard-focusable so Ctrl+C/Ctrl+A work."""
    def _ro_keys(event):
        if event.state & 0x4 and event.keysym.lower() in ("c", "a"):
            return None
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End",
                            "Page_Up", "Page_Down", "Tab",
                            "Shift_L", "Shift_R", "Control_L", "Control_R",
                            "Alt_L", "Alt_R"):
            return None
        return "break"
    text_widget.bind("<KeyPress>", _ro_keys)
    text_widget.bind("<<Paste>>", lambda _e: "break")
    text_widget.bind("<<Cut>>", lambda _e: "break")

BG = "#0d1117"
PANEL = "#161b22"
PANEL2 = "#1f2630"
FG = "#e6edf3"
MUTED = "#8b949e"
ACCENT = "#2f81f7"
RISK_COLORS = {"low": "#5ab0f2", "medium": "#f1b94c", "high": "#ff5252"}
CATEGORY_LABELS = {
    "sqli": "SQL injection",
    "xss": "Cross-site scripting",
    "lfi": "Local file inclusion",
    "ssrf": "Server-side request forgery",
    "open_redirect": "Open redirect",
    "header_injection": "Header injection",
}


class PayloadTesterWindow:
    """A self-contained window. Holds its own scan thread + result queue."""

    def __init__(self, parent_app, default_url: str = ""):
        self.parent_app = parent_app  # back-reference for "save as finding"
        self.win = tk.Toplevel(parent_app.root)
        self.win.title("Payload Tester")
        self.win.geometry("1100x700")
        self.win.minsize(960, 560)
        self.win.configure(bg=BG)

        try:
            self.payloads: list[Payload] = load_payloads()
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Payload Tester", f"Failed to load payload library:\n{e}")
            self.win.destroy()
            return

        self.url_var = StringVar(value=default_url)
        self.method_var = StringVar(value="GET")
        self.param_var = StringVar(value="p")
        self.header_name_var = StringVar(value="X-Forwarded-For")  # for header-injection
        self.category_var = StringVar(value="sqli")
        self.status_var = StringVar(value="Pick a payload and click Send.")

        self._queue: queue.Queue = queue.Queue()
        self._send_thread: threading.Thread | None = None
        self._selected: Payload | None = None
        self._last_send: dict | None = None  # results of the most recent Send

        self._build_ui()
        self._refresh_payload_list()
        self.win.after(40, self._drain_queue)

    # ---------- UI ----------

    def _build_ui(self) -> None:
        # Top: target row
        top = ttk.Frame(self.win, padding=(14, 12, 14, 8))
        top.pack(side="top", fill="x")
        ttk.Label(top, text="Target URL").grid(row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(top, textvariable=self.url_var, font=("Segoe UI", 11)).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Label(top, text="Method").grid(row=0, column=2, sticky="w", padx=(8, 6))
        method_cb = ttk.Combobox(top, textvariable=self.method_var, values=("GET", "POST"), width=6, state="readonly")
        method_cb.grid(row=0, column=3)

        ttk.Label(top, text="Parameter").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=(8, 0))
        ttk.Entry(top, textvariable=self.param_var, width=24).grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Label(top, text="(or Header)").grid(row=1, column=2, sticky="w", padx=(8, 6), pady=(8, 0))
        ttk.Entry(top, textvariable=self.header_name_var, width=24).grid(row=1, column=3, sticky="w", pady=(8, 0))

        top.columnconfigure(1, weight=1)

        # Middle: split into payload picker (left) + payload detail + response (right)
        body = ttk.Panedwindow(self.win, orient="horizontal")
        body.pack(fill="both", expand=True, padx=14, pady=8)

        # ---- Left pane: category dropdown + payload list ----
        left = ttk.Frame(body)
        body.add(left, weight=2)
        cat_row = ttk.Frame(left)
        cat_row.pack(fill="x", pady=(0, 6))
        ttk.Label(cat_row, text="Category:").pack(side="left")
        self.cat_combo = ttk.Combobox(
            cat_row, textvariable=self.category_var,
            values=tuple(VALID_CATEGORIES), state="readonly", width=20,
        )
        self.cat_combo.pack(side="left", padx=(6, 0))
        self.cat_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_payload_list())

        self.payload_list = tk.Listbox(left, bg=PANEL, fg=FG, selectbackground="#1f4f8a",
                                       borderwidth=0, highlightthickness=0,
                                       activestyle="none", font=("Segoe UI", 10))
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.payload_list.yview)
        self.payload_list.configure(yscrollcommand=scroll.set)
        self.payload_list.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.payload_list.bind("<<ListboxSelect>>", lambda _e: self._on_payload_select())

        # ---- Right pane: detail (top) + response viewer (bottom) ----
        right = ttk.Panedwindow(body, orient="vertical")
        body.add(right, weight=3)

        # Detail
        detail_frame = ttk.Frame(right)
        right.add(detail_frame, weight=1)
        self.detail = tk.Text(detail_frame, wrap="word", bg=PANEL, fg=FG, height=10,
                              relief="flat", padx=12, pady=10, font=("Segoe UI", 10),
                              insertbackground=FG)
        self.detail.tag_configure("h1", font=("Segoe UI", 12, "bold"), spacing3=6)
        self.detail.tag_configure("muted", foreground=MUTED)
        self.detail.tag_configure("mono", background=PANEL2, font=("Consolas", 10), lmargin1=8, lmargin2=8, spacing1=4, spacing3=4)
        for risk, color in RISK_COLORS.items():
            self.detail.tag_configure(f"risk_{risk}", foreground=color, font=("Segoe UI", 10, "bold"))
        self.detail.pack(fill="both", expand=True)
        _make_readonly(self.detail)

        # Buttons
        btn_row = ttk.Frame(right)
        right.add(btn_row, weight=0)
        self.send_btn = ttk.Button(btn_row, text="Send (one request)", command=self._on_send, state=DISABLED)
        self.send_btn.pack(side="left", padx=(0, 6), pady=8)
        self.copy_curl_btn = ttk.Button(btn_row, text="Copy as curl", command=self._on_copy_curl, state=DISABLED)
        self.copy_curl_btn.pack(side="left", padx=(0, 6), pady=8)
        self.save_btn = ttk.Button(btn_row, text="Save as finding", command=self._on_save_finding, state=DISABLED)
        self.save_btn.pack(side="left", padx=(0, 6), pady=8)
        ttk.Label(btn_row, textvariable=self.status_var, foreground=MUTED).pack(side="right", padx=8)

        # Response viewer
        resp_frame = ttk.Frame(right)
        right.add(resp_frame, weight=2)
        self.response = tk.Text(resp_frame, wrap="word", bg=PANEL2, fg=FG,
                                relief="flat", padx=12, pady=10, font=("Consolas", 9),
                                insertbackground=FG)
        rscroll = ttk.Scrollbar(resp_frame, orient="vertical", command=self.response.yview)
        self.response.configure(yscrollcommand=rscroll.set)
        self.response.pack(side="left", fill="both", expand=True)
        rscroll.pack(side="right", fill="y")
        self.response.tag_configure("ok", foreground="#6cc474", font=("Consolas", 9, "bold"))
        self.response.tag_configure("warn", foreground="#f1b94c", font=("Consolas", 9, "bold"))
        self.response.tag_configure("err", foreground="#ff5252", font=("Consolas", 9, "bold"))
        _make_readonly(self.response)

    # ---------- Payload list ----------

    def _refresh_payload_list(self) -> None:
        self.payload_list.delete(0, END)
        for p in by_category(self.payloads, self.category_var.get()):
            label = f"[{p.risk.upper():>6}]  {p.title}"
            self.payload_list.insert(END, label)
        # Clear detail when category changes
        self._selected = None
        self.send_btn.configure(state=DISABLED)
        self.copy_curl_btn.configure(state=DISABLED)
        self._set_detail_placeholder()

    def _on_payload_select(self) -> None:
        sel = self.payload_list.curselection()
        if not sel:
            return
        plist = by_category(self.payloads, self.category_var.get())
        if sel[0] >= len(plist):
            return
        self._selected = plist[sel[0]]
        self.send_btn.configure(state=NORMAL)
        self.copy_curl_btn.configure(state=NORMAL)
        self._render_detail(self._selected)

    def _set_detail_placeholder(self) -> None:
        self.detail.delete("1.0", END)
        self.detail.insert(END, "Payload Tester\n", "h1")
        self.detail.insert(END,
            f"Library loaded: {len(self.payloads)} read-only payloads across "
            f"{len(VALID_CATEGORIES)} categories.\n\n"
            "Pick a category on the left, then a payload, then click Send to fire ONE request.\n\n"
            "Safety: every payload is read-only. High-risk payloads (AWS metadata SSRF, "
            "PHP filter source disclosure) will ask for confirmation before sending.",
            "muted",
        )

    def _render_detail(self, p: Payload) -> None:
        self.detail.delete("1.0", END)
        self.detail.insert(END, p.risk.upper(), f"risk_{p.risk}")
        self.detail.insert(END, "   ")
        self.detail.insert(END, p.title + "\n", "h1")
        self.detail.insert(END, CATEGORY_LABELS.get(p.category, p.category) + " Â· " + p.id + "\n", "muted")
        if p.tags:
            self.detail.insert(END, "Tags: " + ", ".join(p.tags) + "\n", "muted")
        self.detail.insert(END, "\n" + p.description + "\n\n")
        self.detail.insert(END, "Payload:\n", "muted")
        self.detail.insert(END, p.payload + "\n", "mono")
        self.detail.insert(END, "\nDetection: ", "muted")
        det = p.detect or {}
        self.detail.insert(END, f"{det.get('match')} = {det.get('match_value')!r}\n", "mono")

    # ---------- Send ----------

    def _on_copy_curl(self) -> None:
        if not self._selected:
            return
        url = self.url_var.get().strip()
        if not url:
            messagebox.showwarning("Payload Tester", "Enter a target URL first.")
            return
        method, params, headers = self._build_request(self._selected, url)
        full_url = urlparse(url)._replace(query="").geturl()
        curl = build_replay_curl(method, full_url, params=params, headers=headers, body=None)
        self.win.clipboard_clear()
        self.win.clipboard_append(curl)
        self.status_var.set("curl command copied to clipboard.")

    def _build_request(self, p: Payload, url: str) -> tuple[str, dict, dict]:
        """Returns (method, params_dict, headers_dict)."""
        method = self.method_var.get()
        params: dict = {}
        headers: dict = {}
        param_name = (self.param_var.get() or "p").strip()
        header_name = (self.header_name_var.get() or "X-Test").strip()
        if p.category == "header_injection":
            headers[header_name] = p.payload
        else:
            params[param_name] = p.payload
        return method, params, headers

    def _on_send(self) -> None:
        if not self._selected:
            return
        if self._send_thread and self._send_thread.is_alive():
            return
        url = self.url_var.get().strip()
        ok_url, why = _validate_target_url(url)
        if not ok_url:
            messagebox.showwarning("Payload Tester", f"Target URL rejected: {why}")
            return
        if self._selected.risk == "high":
            ok = messagebox.askyesno(
                "High-risk payload",
                f"This payload is tagged 'high risk':\n\n"
                f"  {self._selected.title}\n\n"
                f"{self._selected.description}\n\n"
                "Proceed?",
                icon="warning",
            )
            if not ok:
                return

        method, params, headers = self._build_request(self._selected, url)
        self.status_var.set(f"Sending {method} ...")
        self.send_btn.configure(state=DISABLED)
        self._send_thread = threading.Thread(
            target=self._run_send,
            args=(url, method, params, headers, self._selected),
            daemon=True,
        )
        self._send_thread.start()

    def _run_send(self, url: str, method: str, params: dict, headers: dict, p: Payload) -> None:
        """Send via raw httpx so the user's full path + existing query are preserved.
        The wpsecscan Client wrapper assumes base_url is just origin+path and would
        strip the user's ?existing=query."""
        async def go():
            async with httpx.AsyncClient(
                timeout=20.0,
                follow_redirects=False,
                headers={"User-Agent": "WPSecScan/1.0 (payload-tester)"},
                http2=True,
            ) as c:
                t0 = time.perf_counter()
                # httpx merges params with the URL's existing query automatically
                r = await c.request(method, url, params=params, headers=headers)
                duration = time.perf_counter() - t0
                return r, duration

        try:
            r, duration = asyncio.run(go())
        except Exception as e:  # noqa: BLE001
            self._queue.put(("err", f"{type(e).__name__}: {e}"))
            return

        if r is None:
            self._queue.put(("err", "Request returned no response (timeout or transport error)."))
            return

        body = (r.text or "")[:8000]
        headers_out = {k: v for k, v in r.headers.items()}
        triggered, detail = evaluate_response(p, r.status_code, body, headers_out, duration)
        self._queue.put(("done", {
            "payload": p,
            "url": url,
            "method": method,
            "params": params,
            "headers": headers,
            "status_code": r.status_code,
            "reason": getattr(r, "reason_phrase", ""),
            "duration_ms": int(duration * 1000),
            "headers_out": headers_out,
            "body_preview": body[:2000],
            "triggered": triggered,
            "detect_detail": detail,
        }))

    def _drain_queue(self) -> None:
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]
                if kind == "done":
                    self._handle_response(msg[1])
                elif kind == "err":
                    self._handle_error(msg[1])
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.win.after(40, self._drain_queue)

    def _handle_response(self, result: dict) -> None:
        self._last_send = result
        self.send_btn.configure(state=NORMAL)
        self.save_btn.configure(state=NORMAL)
        triggered = result["triggered"]
        self.status_var.set(f"Done â€” {'TRIGGERED' if triggered else 'no trigger'} Â· {result['duration_ms']} ms")

        self.response.delete("1.0", END)
        if triggered:
            self.response.insert(END, "âœ“ TRIGGERED\n", "ok")
        else:
            self.response.insert(END, "Â· not triggered\n", "warn")
        self.response.insert(END, f"  {result['detect_detail']}\n\n")
        self.response.insert(END, f"{result['method']} {result['url']}\n")
        if result['params']:
            self.response.insert(END, f"  params: {result['params']}\n")
        if result['headers']:
            self.response.insert(END, f"  custom headers: {result['headers']}\n")
        self.response.insert(END, f"\nHTTP {result['status_code']} {result['reason']}\n")
        for k in ("content-type", "location", "server", "x-powered-by", "set-cookie",
                  "strict-transport-security", "content-security-policy"):
            v = result["headers_out"].get(k) or result["headers_out"].get(k.title())
            if v:
                self.response.insert(END, f"  {k}: {v}\n")
        self.response.insert(END, "\n--- body (first 2 KB) ---\n")
        self.response.insert(END, result["body_preview"] or "(empty)")

    def _handle_error(self, err: str) -> None:
        self.send_btn.configure(state=NORMAL)
        self.status_var.set(f"Error: {err}")
        self.response.delete("1.0", END)
        self.response.insert(END, "âœ— " + err + "\n", "err")

    # ---------- Save as finding ----------

    def _on_save_finding(self) -> None:
        if not self._last_send:
            return
        r = self._last_send
        p = r["payload"]
        severity = "high" if r["triggered"] and p.risk == "high" else (
            "medium" if r["triggered"] else "info"
        )
        replay = build_replay_curl(r["method"], r["url"], params=r["params"], headers=r["headers"], body=None)
        finding = Finding(
            severity=severity,
            title=("[PAYLOAD TESTER] " + p.title + (" â€” TRIGGERED" if r["triggered"] else " â€” no trigger")),
            evidence=(
                f"Payload library: {p.id}\n"
                f"{r['method']} {r['url']}\n"
                f"  params={r['params']}\n"
                f"  custom headers={r['headers']}\n"
                f"  -> HTTP {r['status_code']}\n"
                f"  detection: {r['detect_detail']}\n"
            ),
            remediation=("Triggered â€” investigate and patch." if r["triggered"]
                         else "No trigger from this payload."),
            url=r["url"],
            extra={"replay": replay, "payload_id": p.id, "category": p.category, "risk": p.risk},
        )
        # Wire into the parent app's current report
        ok = self.parent_app._add_payload_tester_finding(finding)  # noqa: SLF001
        if ok:
            self.status_var.set("Saved to the main scan report.")
        else:
            messagebox.showinfo("Payload Tester",
                "No active scan report â€” run a scan first, then come back to this window to save findings into it.")


def open_payload_tester(parent_app, default_url: str = "") -> None:
    """Entry point â€” called from gui.py's Tools menu."""
    PayloadTesterWindow(parent_app, default_url=default_url)

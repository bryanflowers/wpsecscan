"""Round-59 #95-97 — Browser visit replay tooling.

Optional — uses Playwright if installed. All entry points return ""
or empty list when Playwright isn't available.

#95 Playwright attacker-session recorder — given a list of paths,
    record an authenticated session as a Playwright trace.
#96 Visual diff between scans — wrap an old report HTML and a new
    report HTML and produce per-finding diff markers.
#97 Attacker-view video export — convert the Playwright trace into
    an .mp4 (requires ffmpeg). Helpful for executive demos.
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
from pathlib import Path


def _has_playwright() -> bool:
    try:
        import playwright  # type: ignore[import-untyped]  # noqa: F401
        return True
    except ImportError:
        return False


def _safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", s or "")[:80] or "out"


# ---- #95 Recorder ----

def record_attacker_session(target: str, paths: list[str], cookies: list[dict],
                              out_dir: str | Path) -> str:
    """Record a navigation through `paths` with the supplied auth cookies.

    Returns path to the trace ZIP, or "" if Playwright is unavailable /
    fails. Saves under `out_dir/trace_<safe>.zip`.
    """
    if not _has_playwright():
        return ""
    out = Path(out_dir)
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        return ""
    trace_path = out / f"trace_{_safe_name(target)}.zip"
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx = browser.new_context()
            if cookies:
                # filter unsafe cookies
                safe_cookies = [c for c in cookies
                                 if isinstance(c, dict) and c.get("name") and c.get("domain")]
                if safe_cookies:
                    ctx.add_cookies(safe_cookies)
            ctx.tracing.start(screenshots=True, snapshots=True, sources=False)
            page = ctx.new_page()
            for p in paths[:50]:  # cap
                try:
                    url = p if p.startswith(("http://", "https://")) else target.rstrip("/") + "/" + p.lstrip("/")
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:  # noqa: BLE001
                    continue
            ctx.tracing.stop(path=str(trace_path))
            browser.close()
        return str(trace_path)
    except Exception:  # noqa: BLE001
        return ""


# ---- #96 Visual diff between two scan reports ----

def diff_reports(old_path: str | Path, new_path: str | Path) -> str:
    """Return a unified diff string highlighting changes between two report
    HTMLs. Returns "" on failure."""
    try:
        old = Path(old_path).read_text(encoding="utf-8", errors="replace")
        new = Path(new_path).read_text(encoding="utf-8", errors="replace")
    except (OSError, FileNotFoundError):
        return ""
    old_lines = [l for l in old.splitlines() if l.strip()]
    new_lines = [l for l in new.splitlines() if l.strip()]
    diff = difflib.unified_diff(old_lines, new_lines,
                                  fromfile=str(old_path), tofile=str(new_path),
                                  lineterm="", n=2)
    return "\n".join(list(diff)[:2000])  # truncate


# ---- #97 Attacker-view video export ----

def trace_to_video(trace_zip: str | Path, out_mp4: str | Path) -> str:
    """Use ffmpeg to stitch the trace's screenshots into an mp4. Returns
    the output path or "" on failure.

    Playwright traces are zipped; we extract them to a temp dir and feed
    the resources/<n>.jpeg images into ffmpeg.
    """
    if not shutil.which("ffmpeg"):
        return ""
    import tempfile
    import zipfile
    try:
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(str(trace_zip), "r") as zf:
                zf.extractall(tmp)
            # find frame jpegs
            resources = Path(tmp) / "resources"
            if not resources.exists():
                return ""
            jpegs = sorted(resources.glob("*.jpeg"))
            if not jpegs:
                return ""
            # symlink to sequential names
            seq_dir = Path(tmp) / "seq"
            seq_dir.mkdir()
            for i, j in enumerate(jpegs[:1000]):
                shutil.copy(j, seq_dir / f"frame_{i:05d}.jpg")
            out = Path(out_mp4)
            out.parent.mkdir(parents=True, exist_ok=True)
            cmd = ["ffmpeg", "-y", "-framerate", "4",
                    "-i", str(seq_dir / "frame_%05d.jpg"),
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", str(out)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode != 0 or not out.exists():
                return ""
            return str(out)
    except (OSError, zipfile.BadZipFile, subprocess.TimeoutExpired):
        return ""

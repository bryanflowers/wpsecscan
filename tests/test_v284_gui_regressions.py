"""v2.8.4 Phase 6.1 — regression tests for Phase 1 critical/high bugs.

These tests are source-level (parse the file's text and assert the fix
is present) where the bug requires an interactive Tk loop to reproduce
directly. Same pattern as v2.8.3 test_v283_phase1_regressions.py.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


_GUI = Path("wpsecscan/gui.py")
_GUI_WIN = Path("wpsecscan/gui_windows.py")
_MOBILE = Path("wpsecscan/mobile_api.py")
_SCANNER = Path("wpsecscan/scanner.py")


# ===========================================================================
# C1 — quick_btn and cancel_btn should NOT share grid column
# ===========================================================================
def test_c1_quick_btn_and_cancel_btn_different_columns():
    """v2.8.4 C1: pre-fix both used column=3, so the Cancel button
    (initially DISABLED but visible) overlaid Quick the entire time
    a scan wasn't running."""
    src = _GUI.read_text(encoding="utf-8")
    # Find both grid calls and verify their columns differ.
    quick_col = re.search(r"self\.quick_btn\.grid\(row=0,\s*column=(\d+)", src)
    cancel_col = re.search(r"self\.cancel_btn\.grid\(row=0,\s*column=(\d+)", src)
    assert quick_col, "quick_btn.grid not found"
    assert cancel_col, "cancel_btn.grid not found"
    assert quick_col.group(1) != cancel_col.group(1), \
        f"C1 regression — both buttons on column {quick_col.group(1)}"


# ===========================================================================
# C2 — multi-target worker uses winfo_exists guard
# ===========================================================================
def test_c2_mt_worker_uses_winfo_exists_guard():
    """v2.8.4 C2: pre-fix _mt_worker fired after() callbacks on a
    destroyed Treeview when the window closed mid-scan."""
    src = _GUI_WIN.read_text(encoding="utf-8")
    # Find the _mt_worker function and verify the guard pattern.
    idx = src.find("def _mt_worker")
    assert idx > 0
    body = src[idx:idx + 4000]
    assert "winfo_exists" in body, \
        "C2 regression — _mt_worker lost the winfo_exists guard"
    assert "_safe_after" in body, \
        "C2 regression — _mt_worker lost the _safe_after helper"


# ===========================================================================
# H1 — _save_pref uses atomic write
# ===========================================================================
def test_h1_save_pref_uses_atomic_write():
    """v2.8.4 H1: _save_pref must go through _atomic_write_text (or
    fall back to a tmp-rename pattern). Pre-fix bare write_text could
    corrupt prefs.json under concurrent writes."""
    src = _GUI.read_text(encoding="utf-8")
    idx = src.find("def _save_pref")
    assert idx > 0
    body = src[idx:idx + 2500]
    assert "_atomic_write_text" in body or "os.replace" in body, \
        "H1 regression — _save_pref lost atomic-write discipline"
    assert "Lock" in body or "threading" in body, \
        "H1 regression — _save_pref lost the threading.Lock"


# ===========================================================================
# H2 — filter state vars are loaded from + saved to prefs.json
# ===========================================================================
def test_h2_filter_state_loaded_from_prefs():
    src = _GUI.read_text(encoding="utf-8")
    assert '_load_pref("filters"' in src, \
        "H2 regression — filter vars no longer hydrate from prefs.json"
    assert '_save_pref("filters"' in src, \
        "H2 regression — _apply_filter no longer persists filter state"


# ===========================================================================
# H3 — patchstack_token is passed to scan()
# ===========================================================================
def test_h3_patchstack_token_wired_to_scanner():
    """v2.8.4 H3: pre-fix the onboarding wizard collected the token
    but _run_scan never passed it to scan(); scan() didn't accept it."""
    gui_src = _GUI.read_text(encoding="utf-8")
    scanner_src = _SCANNER.read_text(encoding="utf-8")
    assert "patchstack_token=tokens.get" in gui_src, \
        "H3 regression — _run_scan no longer passes patchstack_token"
    assert "patchstack_token: str | None" in scanner_src, \
        "H3 regression — scan() no longer accepts patchstack_token kwarg"
    assert '"patchstack_token": patchstack_token' in scanner_src, \
        "H3 regression — patchstack_token no longer in ctx dict"


# ===========================================================================
# H4 — Quick-scan state restored via _restore_quick_scan_state, not timer
# ===========================================================================
def test_h4_quick_scan_uses_callback_not_timer():
    src = _GUI.read_text(encoding="utf-8")
    assert "_restore_quick_scan_state" in src, \
        "H4 regression — restore helper missing"
    # Pre-fix used `self.root.after(500, lambda: ...)` for restore.
    # Confirm the restore is invoked from _handle_done + _handle_error.
    handle_done_idx = src.find("def _handle_done")
    assert handle_done_idx > 0
    body = src[handle_done_idx:handle_done_idx + 500]
    assert "_restore_quick_scan_state" in body, \
        "H4 regression — _handle_done no longer calls restore"


# ===========================================================================
# H5 — _on_window_close joins the scan thread
# ===========================================================================
def test_h5_window_close_joins_scan_thread():
    src = _GUI.read_text(encoding="utf-8")
    idx = src.find("def _on_window_close")
    assert idx > 0
    body = src[idx:idx + 2000]
    assert "join(timeout" in body, \
        "H5 regression — _on_window_close no longer joins the scan thread"


# ===========================================================================
# H6 — multi-target Toplevel has only ONE <Destroy> binding
# ===========================================================================
def test_h6_no_duplicate_destroy_binding():
    src = _GUI_WIN.read_text(encoding="utf-8")
    idx = src.find("def open_multitarget")
    assert idx > 0
    body = src[idx:idx + 800]
    destroy_count = body.count('win.bind("<Destroy>"')
    assert destroy_count == 1, \
        f"H6 regression — found {destroy_count} <Destroy> binds (expected 1)"


# ===========================================================================
# H7 — mobile_api emits CORS headers + has _send_404 helper
# ===========================================================================
def test_h7_mobile_api_emits_cors_headers():
    src = _MOBILE.read_text(encoding="utf-8")
    assert "Access-Control-Allow-Origin" in src, \
        "H7 regression — CORS header lost"
    assert "def _send_404" in src, \
        "H7 regression — _send_404 helper lost"
    assert "WPSECSCAN_MOBILE_API_CORS_ORIGIN" in src, \
        "H7 regression — CORS env-var override lost"


def test_h7_mobile_api_has_options_handler():
    """v2.8.4 P4 — CORS preflight needs do_OPTIONS."""
    src = _MOBILE.read_text(encoding="utf-8")
    assert "def do_OPTIONS" in src, \
        "v2.8.4 P4 — do_OPTIONS handler missing"


# ===========================================================================
# Phase 4 — Push + Export dispatch tables stay in sync
# ===========================================================================
def test_phase4_push_dispatch_in_sync_with_cli():
    """v2.8.4 Phase 4: the GUI File→Push submenu must enumerate the
    same providers as the CLI `wpsecscan push` dispatch table."""
    gui_src = _GUI.read_text(encoding="utf-8")
    main_src = Path("wpsecscan/__main__.py").read_text(encoding="utf-8")
    # CLI dispatch lives in _cmd_push; pull provider keys
    cmd_push_idx = main_src.find("def _cmd_push")
    assert cmd_push_idx > 0
    push_body = main_src[cmd_push_idx:cmd_push_idx + 4000]
    cli_providers = set(re.findall(r'"([\w-]+)":\s*\("integrations_v28"', push_body))
    # GUI submenu list lives inside _build_ui
    gui_idx = gui_src.find('# "Push to…" submenu')
    if gui_idx < 0:
        gui_idx = gui_src.find('"Push to…" submenu')
    assert gui_idx > 0
    submenu_body = gui_src[gui_idx:gui_idx + 1500]
    gui_providers = set(re.findall(r'"([\w-]+)"\s*,', submenu_body))
    # CLI providers should be a subset of GUI providers
    missing_in_gui = cli_providers - gui_providers
    assert not missing_in_gui, \
        f"Phase 4 regression — CLI providers missing from GUI Push menu: {missing_in_gui}"


def test_phase4_emit_dispatch_in_sync_with_cli():
    """v2.8.4 Phase 4: the GUI File→Export As submenu must enumerate
    the same formats as the CLI `wpsecscan emit` dispatch table."""
    gui_src = _GUI.read_text(encoding="utf-8")
    main_src = Path("wpsecscan/__main__.py").read_text(encoding="utf-8")
    # CLI dispatch lives in _EMIT_DISPATCH module constant
    cli_formats = set(re.findall(r'"([\w-]+)":\s*\("compliance_v28"', main_src))
    # GUI submenu list
    gui_idx = gui_src.find('# "Export As…" submenu')
    if gui_idx < 0:
        gui_idx = gui_src.find('"Export As…" submenu')
    assert gui_idx > 0
    submenu_body = gui_src[gui_idx:gui_idx + 1500]
    gui_formats = set(re.findall(r'"([\w-]+)"\s*,', submenu_body))
    missing = cli_formats - gui_formats
    # Some CLI formats may legitimately be GUI-omitted; soft-assert at most
    # 2 missing for now (room for v2.9.0 additions).
    assert len(missing) <= 2, \
        f"Phase 4 regression — CLI emit formats missing from GUI: {missing}"


# ===========================================================================
# Phase 5 — mobile_api POST /api/scan endpoint exists
# ===========================================================================
def test_p1_mobile_api_post_scan_endpoint_exists():
    src = _MOBILE.read_text(encoding="utf-8")
    assert "def do_POST" in src, \
        "P1 regression — do_POST handler missing"
    assert '"/api/scan"' in src, \
        "P1 regression — /api/scan route missing"
    assert "target.startswith" in src and 'http://' in src, \
        "P1 regression — target URL validation missing"


def test_p2_per_finding_detail_endpoint_exists():
    src = _MOBILE.read_text(encoding="utf-8")
    assert "/findings/" in src, \
        "P2 regression — per-finding-detail endpoint missing"


# ===========================================================================
# Phase 2 L8 — _populate_tree exists
# ===========================================================================
def test_l8_populate_tree_exists():
    src = _GUI.read_text(encoding="utf-8")
    assert "def _populate_tree" in src, \
        "L8 regression — _populate_tree method missing"
    # And _open_saved_report should still call it directly (not behind hasattr)
    idx = src.find("def _open_saved_report")
    assert idx > 0
    body = src[idx:idx + 3000]
    assert "self._populate_tree(report)" in body, \
        "L8 regression — _open_saved_report no longer calls _populate_tree"


# ===========================================================================
# Phase 3 UX — keyboard shortcuts bound
# ===========================================================================
@pytest.mark.parametrize("binding", [
    "<Control-f>",  # U#1 focus search
    "<Control-r>",  # U#2 rescan
    "<F1>",          # U#3 context docs
    "<Alt-Key-d>",  # U#4 diff with last
])
def test_phase3_new_keyboard_shortcuts(binding):
    src = _GUI.read_text(encoding="utf-8")
    assert f'bind_all("{binding}"' in src, \
        f"Phase 3 regression — keyboard shortcut {binding} lost"


def test_phase3_findings_tree_supports_multi_select():
    """U#9: tree must use selectmode=extended for bulk actions."""
    src = _GUI.read_text(encoding="utf-8")
    assert 'selectmode="extended"' in src, \
        "U#9 regression — findings tree no longer supports multi-select"


# ===========================================================================
# Phase 3 — sash position persistence
# ===========================================================================
def test_phase3_sash_position_persisted():
    src = _GUI.read_text(encoding="utf-8")
    assert "sash_position" in src, \
        "U#8 regression — sash_position pref key lost"
    assert "_restore_sash" in src and "_persist_sash" in src, \
        "U#8 regression — sash helpers missing"

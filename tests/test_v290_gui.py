"""v2.9.0 — headless regression tests for wpsecscan/gui.py.

AST-level assertions (no Tk window is ever opened) plus one behavioural test
that drives App._run_scan on an un-initialised App with a patched scan().
"""
from __future__ import annotations

import ast
import types
from pathlib import Path

import pytest

_GUI = Path(__file__).resolve().parent.parent / "wpsecscan" / "gui.py"


@pytest.fixture(scope="module")
def tree() -> ast.Module:
    return ast.parse(_GUI.read_text(encoding="utf-8"))


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return ""


# ---------------------------------------------------------------------------
# (a) every scan(...) call that passes aggressive= also passes consent=
# ---------------------------------------------------------------------------
def test_every_scan_call_with_aggressive_passes_consent(tree):
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and _call_name(n) == "scan"]
    assert calls, "expected at least one scan( call in gui.py"
    for c in calls:
        kws = {k.arg for k in c.keywords}
        if "aggressive" in kws:
            assert "consent" in kws, \
                f"gui.py:{c.lineno} scan(aggressive=...) without consent="


# ---------------------------------------------------------------------------
# (b) json is importable where json.loads/dumps is used
# ---------------------------------------------------------------------------
def test_json_imported_at_module_level(tree):
    for node in tree.body:
        if isinstance(node, ast.Import):
            if any(a.name == "json" and a.asname is None for a in node.names):
                return
    pytest.fail("gui.py has no module-level `import json` (W1c: _worker NameError)")


# ---------------------------------------------------------------------------
# (c) no lambda references a name bound by an enclosing `except ... as name`
# ---------------------------------------------------------------------------
def _lambda_except_name_leaks(tree: ast.Module) -> list[tuple[int, str]]:
    leaks: list[tuple[int, str]] = []

    def visit_stmts(stmts, bound: frozenset[str]) -> None:
        for st in stmts:
            walk(st, bound)

    def walk(node: ast.AST, bound: frozenset[str]) -> None:
        if isinstance(node, ast.ExceptHandler):
            inner = bound | ({node.name} if node.name else frozenset())
            for ch in node.body:
                walk(ch, frozenset(inner))
            return
        if isinstance(node, ast.Lambda) and bound:
            params = {a.arg for a in node.args.args + node.args.kwonlyargs}
            if node.args.vararg:
                params.add(node.args.vararg.arg)
            if node.args.kwarg:
                params.add(node.args.kwarg.arg)
            for n in ast.walk(node.body):
                if isinstance(n, ast.Name) and n.id in bound and n.id not in params:
                    leaks.append((node.lineno, n.id))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A nested def starts a new scope: names bound by an outer
            # except are still deleted at the end of that except block.
            visit_stmts(node.body, bound)
            return
        for ch in ast.iter_child_nodes(node):
            walk(ch, bound)

    walk(tree, frozenset())
    return leaks


def test_no_lambda_captures_except_name(tree):
    assert _lambda_except_name_leaks(tree) == []


def test_except_name_walker_detects_the_bug():
    bad = ast.parse(
        "def f(root):\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        root.after(0, lambda: print(e))\n"
    )
    assert _lambda_except_name_leaks(bad) == [(5, "e")]
    good = ast.parse(
        "def f(root):\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        msg = str(e)\n"
        "        root.after(0, lambda: print(msg))\n"
    )
    assert _lambda_except_name_leaks(good) == []


# ---------------------------------------------------------------------------
# (d) docs deep-link goes to the repo markdown until site pages exist
# ---------------------------------------------------------------------------
def test_docs_url_constant_points_at_repo_markdown(tree):
    consts = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    consts[t.id] = node.value.value
    assert "github.com/bryanflowers/wpsecscan/blob/main/docs/checks/" in \
        consts.get("_CHECK_DOCS_URL_BASE", "")
    src = _GUI.read_text(encoding="utf-8")
    assert "wpsecscan.com/docs/checks/" not in src
    assert '"https://wpsecscan.com/docs/"' in src


def test_tooltip_describes_real_consent_mechanisms():
    src = _GUI.read_text(encoding="utf-8")
    assert "--owned" in src and "owned add" in src


# ---------------------------------------------------------------------------
# Behavioural: aggressive confirm path -> scan(consent=True)
# ---------------------------------------------------------------------------
class _Var:
    def __init__(self, v):
        self._v = v

    def get(self):
        return self._v


def _bare_app(monkeypatch, captured):
    gui = pytest.importorskip("wpsecscan.gui")
    from wpsecscan import gui_windows

    async def fake_scan(target, **kw):
        captured.update(kw)
        return "REPORT"

    monkeypatch.setattr(gui, "scan", fake_scan)
    monkeypatch.setattr(gui_windows, "_load_setup_tokens", lambda: {})
    app = object.__new__(gui.App)
    app.auth_user_var = _Var("")
    app.auth_pass_var = _Var("")
    app.prove_var = _Var(False)
    app.deep_throttle_var = _Var(False)
    app.deep_throttle_attempts_var = _Var(120)
    app.deep_throttle_pacing_var = _Var(10.0)
    app.http_timeout_var = _Var(15.0)
    app._cancel_requested = False
    app._pause_requested = False
    app._queue = __import__("queue").Queue()
    return gui, app


def test_run_scan_passes_consent_true_after_confirm(monkeypatch):
    captured: dict = {}
    _gui, app = _bare_app(monkeypatch, captured)
    app._run_scan("https://example.test", True, True)
    assert captured["aggressive"] is True
    assert captured["consent"] is True
    assert app._queue.get_nowait() == ("done", "REPORT")


def test_run_scan_without_confirm_does_not_grant_consent(monkeypatch):
    captured: dict = {}
    _gui, app = _bare_app(monkeypatch, captured)
    app._run_scan("https://example.test", True)  # profile-load style: no confirm
    assert captured["consent"] is None
    captured.clear()
    app._run_scan("https://example.test", False, True)  # passive: never consent
    assert captured["consent"] is None


def test_aggressive_toggle_yes_sets_confirmed_no_clears(monkeypatch):
    gui = pytest.importorskip("wpsecscan.gui")
    app = object.__new__(gui.App)
    state = {"on": True}
    app.aggressive_var = types.SimpleNamespace(
        get=lambda: state["on"], set=lambda v: state.__setitem__("on", v))
    app._aggressive_confirmed = False

    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    app._on_aggressive_toggle()
    assert app._aggressive_confirmed is True and state["on"] is True

    state["on"] = True
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: False)
    app._on_aggressive_toggle()
    assert app._aggressive_confirmed is False and state["on"] is False


def _consent_app(gui, entry_url="", aggressive=True):
    """Un-initialised App with just the widgets the aggressive-consent path reads."""
    app = object.__new__(gui.App)
    state = {"on": aggressive}
    app.aggressive_var = types.SimpleNamespace(
        get=lambda: state["on"], set=lambda v: state.__setitem__("on", v))
    app.url_var = types.SimpleNamespace(get=lambda: entry_url)
    app.url_entry = types.SimpleNamespace(_placeholder_active=False)
    app._aggressive_confirmed = False
    app._aggressive_confirmed_host = None
    return app, state


def test_toggle_confirmation_is_bound_to_the_entry_host(monkeypatch):
    gui = pytest.importorskip("wpsecscan.gui")
    app, _state = _consent_app(gui, "https://A.example/")
    asked: list = []
    monkeypatch.setattr(app, "_ask_aggressive_confirm",
                        lambda host=None: asked.append(host) or True)
    app._on_aggressive_toggle()
    assert asked == ["a.example"]
    assert app._aggressive_confirmed is True
    assert app._aggressive_confirmed_host == "a.example"


def test_changing_target_after_confirm_reprompts_and_no_means_passive(monkeypatch):
    gui = pytest.importorskip("wpsecscan.gui")
    app, state = _consent_app(gui)
    app._aggressive_confirmed = True
    app._aggressive_confirmed_host = "a.example"
    asked: list = []

    # Same host: confirmation on record is reused, no dialog.
    monkeypatch.setattr(app, "_ask_aggressive_confirm",
                        lambda host=None: asked.append(host) or False)
    assert app._aggressive_scan_consent("a.example") is True
    assert asked == []

    # Different host: must re-prompt; a No drops consent and aggressive.
    assert app._aggressive_scan_consent("b.example") is None
    assert asked == ["b.example"]
    assert state["on"] is False
    assert app._aggressive_confirmed is False and app._aggressive_confirmed_host is None


def test_changing_target_after_confirm_yes_rebinds_to_new_host(monkeypatch):
    gui = pytest.importorskip("wpsecscan.gui")
    app, state = _consent_app(gui)
    app._aggressive_confirmed = True
    app._aggressive_confirmed_host = "a.example"
    monkeypatch.setattr(app, "_ask_aggressive_confirm", lambda host=None: True)
    assert app._aggressive_scan_consent("b.example") is True
    assert app._aggressive_confirmed_host == "b.example"
    assert state["on"] is True


def test_confirmation_without_a_bound_host_does_not_cover_any_host(monkeypatch):
    gui = pytest.importorskip("wpsecscan.gui")
    app, _state = _consent_app(gui, "")  # toggled before a URL was typed
    monkeypatch.setattr(app, "_ask_aggressive_confirm", lambda host=None: True)
    app._on_aggressive_toggle()
    assert app._aggressive_confirmed_host is None
    asked: list = []
    monkeypatch.setattr(app, "_ask_aggressive_confirm",
                        lambda host=None: asked.append(host) or False)
    assert app._aggressive_scan_consent("a.example") is None
    assert asked == ["a.example"]


def test_passive_scan_never_gets_consent(monkeypatch):
    gui = pytest.importorskip("wpsecscan.gui")
    app, _state = _consent_app(gui, aggressive=False)
    app._aggressive_confirmed = True
    app._aggressive_confirmed_host = "a.example"
    assert app._aggressive_scan_consent("a.example") is None


def test_toggle_off_clears_the_bound_host():
    gui = pytest.importorskip("wpsecscan.gui")
    app, _state = _consent_app(gui, aggressive=False)
    app._aggressive_confirmed = True
    app._aggressive_confirmed_host = "a.example"
    app._on_aggressive_toggle()
    assert app._aggressive_confirmed is False and app._aggressive_confirmed_host is None


def test_scan_click_uses_host_bound_consent_helper(tree):
    src = _GUI.read_text(encoding="utf-8")
    assert "_aggressive_scan_consent(" in src
    # the old session-wide gate must not be reintroduced in _on_scan_click
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_on_scan_click")
    assert "_aggressive_confirmed" not in ast.unparse(fn)


def test_remember_owned_adds_host_only_on_yes(monkeypatch, tmp_path):
    gui = pytest.importorskip("wpsecscan.gui")
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    monkeypatch.delenv("WPSECSCAN_OWNED_TARGETS", raising=False)
    from wpsecscan import consent

    app = object.__new__(gui.App)
    app._owned_prompted = set()
    app.status_var = types.SimpleNamespace(set=lambda v: None)

    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: False)
    app._maybe_remember_owned("https://Site.Example/")
    assert "site.example" not in consent.load_owned()

    app._owned_prompted.clear()
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)
    app._maybe_remember_owned("https://Site.Example/")
    assert "site.example" in consent.load_owned()

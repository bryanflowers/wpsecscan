"""v2.7.0 CLI extras (F82-F87).

Small helpers / handlers for the CLI items added in v2.7.0.

  F82 --quiet           argparse alias for --no-console (handled inline).
  F83 enable_win_ansi() enable VT-mode for legacy cmd.exe / PowerShell.
  F84 SubProgress       per-sub-probe progress wrapper (used by aggressive
                          checks; the live dashboard reads .extra['sub_progress']).
  F85 cmd_replay_prompt TUI walking the most-recent scan's failed checks.
  F86 cmd_install_completion  writes a shell-completion file + source line.
  F87 session log + cmd_undo  ~/.wpsecscan/session-log.json + revert.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from ._util import home_dir, load_home_json


# ---------------------------------------------------------------------------
# F83 — enable VT mode on legacy Windows consoles
# ---------------------------------------------------------------------------

def enable_win_ansi() -> bool:
    """Enable VT-mode ANSI processing on Windows cmd.exe / PowerShell.
    Returns True if enabling succeeded, False if not Windows / failed."""
    if sys.platform != "win32":
        return True  # nothing to do
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        ENABLE_VT = 0x0004
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(handle, mode.value | ENABLE_VT)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# F86 — `wpsecscan --install-completion`
# ---------------------------------------------------------------------------

def cmd_install_completion(args: list[str]) -> None:
    """Detect the operator's shell and install the matching completion.

    Heuristic: $SHELL env var → bash | zsh | fish. Falls back to bash.
    Writes to:
      ~/.bash_completion.d/wpsecscan (bash)
      ~/.zfunc/_wpsecscan (zsh)
      ~/.config/fish/completions/wpsecscan.fish (fish)
    """
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        target = Path.home() / ".zfunc" / "_wpsecscan"
        backend = "zsh"
    elif "fish" in shell:
        target = Path.home() / ".config" / "fish" / "completions" / "wpsecscan.fish"
        backend = "fish"
    else:
        target = Path.home() / ".bash_completion.d" / "wpsecscan"
        backend = "bash"
    try:
        from .completion import generate
        content = generate(backend)
    except (ImportError, AttributeError, ValueError):
        print(f"wpsecscan.completion.generate({backend!r}) unavailable",
              file=sys.stderr)
        sys.exit(2)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    print(f"installed {backend} completion: {target}")
    print(f"# Source it now: . {target}")


# ---------------------------------------------------------------------------
# F85 — `wpsecscan replay-prompt`
# ---------------------------------------------------------------------------

def cmd_replay_prompt(args: list[str]) -> None:
    """TUI: walk the most-recent scan's high-severity findings, ask
    per-finding action. Stdin-driven (no curses dependency)."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan replay-prompt URL", file=sys.stderr); sys.exit(64)
    url = args[0]
    if "://" not in url:
        url = "https://" + url
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved scan for {url}", file=sys.stderr); sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    actions: list[dict] = []
    for r in data.get("results", []):
        for f in r.get("findings", []):
            if f.get("severity") not in ("high", "critical"):
                continue
            print()
            print(f"[{f['severity']:8s}] {r['check_id']}: {f.get('title')}")
            print(f"           {(f.get('evidence') or '')[:200]}")
            try:
                ans = input("[s]nooze 30d / [r]aise / [j]ira / [i]gnore: ").strip().lower()
            except EOFError:
                break
            if ans in ("s", "r", "j"):
                actions.append({"action": ans, "check_id": r["check_id"],
                                  "title": f.get("title", "")})
    if actions:
        log_p = home_dir() / "replay-prompt-log.json"
        existing = load_home_json("replay-prompt-log.json", [])
        existing.extend(actions)
        # B8 (v2.7.1) — atomic temp+rename so concurrent replay sessions
        # can't corrupt the log mid-write.
        tmp_p = log_p.with_suffix(f".json.tmp.{os.getpid()}")
        tmp_p.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        os.replace(tmp_p, log_p)
        print(f"\n{len(actions)} action(s) logged to {log_p}")


# ---------------------------------------------------------------------------
# F87 — `wpsecscan undo`
# ---------------------------------------------------------------------------

_SESSION_LOG = "session-log.json"


def log_action(action: str, payload: dict) -> None:
    """Public hook other modules call before mutating user state."""
    log = load_home_json(_SESSION_LOG, [])
    log.append({"ts": int(time.time()), "action": action, "payload": payload})
    log = log[-200:]  # keep last 200 entries
    p = home_dir() / _SESSION_LOG
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(log, indent=2), encoding="utf-8")
    except OSError:
        pass


def cmd_undo(args: list[str]) -> None:
    """Print the last recorded session action + give the operator the
    revert command. Not auto-undo — too risky to silently revert state.
    """
    log = load_home_json(_SESSION_LOG, [])
    if not log:
        print("Session log is empty — nothing to undo.")
        return
    last = log[-1]
    print(f"Last action: {last['action']}")
    print(f"  Payload:    {json.dumps(last['payload'])[:200]}")
    print(f"  Timestamp:  {last['ts']}")
    print()
    a = last["action"]
    p = last.get("payload", {})
    # Suggested revert commands
    if a == "creds-set":
        print(f"# To revert: wpsecscan creds rm '{p.get('site_url','')}' --field '{p.get('field','')}'")
    elif a == "snooze-add":
        print(f"# To revert: edit ~/.wpsecscan/snoozes.json and remove the matching entry")
    elif a == "policy-mutation":
        print(f"# To revert: edit ~/.wpsecscan/policy.yml — the mutation was in section: {p.get('section','?')}")
    elif a == "cron-schedule-add":
        print(f"# To revert: wpsecscan cron-schedule rm '{p.get('name','')}'")
    else:
        print(f"# No specific revert command for action: {a}")
        print(f"# Inspect: cat ~/.wpsecscan/{_SESSION_LOG}")

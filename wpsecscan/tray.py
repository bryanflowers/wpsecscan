"""Item #56 — minimize-to-tray for the WPSecScan GUI.

When pystray + Pillow are installed (`pip install wpsecscan[ui]`), the GUI
hides to a system-tray icon on close instead of exiting, with a right-click
menu to restore or quit. When either dependency is missing, start_tray()
is a no-op — the GUI behaves exactly as it did before this commit.

Scope is deliberately minimal: no IPC with `wpsecscan watch` daemons,
no per-scan state colouring. The tray icon exists so the GUI can sit
quietly in the system tray and be re-summoned later without going through
the launcher.
"""
from __future__ import annotations

import threading
from typing import Any


def _build_icon_image():
    """Procedurally draw a 64×64 RGBA shield icon so we don't need to
    vendor a binary .ico file. Returns a PIL Image."""
    from PIL import Image, ImageDraw  # type: ignore[import-not-found]
    img = Image.new("RGBA", (64, 64), (13, 17, 23, 255))  # WPSecScan bg
    draw = ImageDraw.Draw(img)
    # Outer rounded "shield".
    draw.rounded_rectangle((4, 4, 60, 60), radius=10,
                            fill=(35, 79, 167, 255),  # blue
                            outline=(121, 192, 255, 255),
                            width=2)
    # "W" — three thick strokes.
    draw.line([(16, 18), (24, 46)], fill="white", width=4)
    draw.line([(24, 46), (32, 26)], fill="white", width=4)
    draw.line([(32, 26), (40, 46)], fill="white", width=4)
    draw.line([(40, 46), (48, 18)], fill="white", width=4)
    return img


def start_tray(app) -> Any | None:
    """Spawn a pystray Icon for the app's Tk window. Returns the Icon (so
    callers can stop it on shutdown), or None when the optional deps are
    missing or the icon cannot be created."""
    try:
        import pystray  # type: ignore[import-not-found]  # noqa: PLC0415
    except ImportError:
        return None
    try:
        image = _build_icon_image()
    except ImportError:
        # Pillow missing (or stripped from a frozen build) — abort silently.
        return None

    def _on_show(icon, _item):  # noqa: ARG001
        # pystray callbacks run on its own thread; use Tk's threadsafe
        # scheduler to bounce the action back to the main loop.
        try:
            app.root.after(0, _show_window, app)
        except Exception:  # noqa: BLE001
            pass

    def _on_quit(icon, _item):  # noqa: ARG001
        try:
            icon.stop()
        finally:
            try:
                app.root.after(0, app.root.destroy)
            except Exception:  # noqa: BLE001
                pass

    menu = pystray.Menu(
        pystray.MenuItem("Show WPSecScan", _on_show, default=True),
        pystray.MenuItem("Quit",           _on_quit),
    )
    icon = pystray.Icon("wpsecscan", image, "WPSecScan", menu=menu)
    # Stash a reference on the app so the close handler can call icon.stop().
    app._tray_icon = icon  # type: ignore[attr-defined]

    # pystray's run() is blocking; we want it to live alongside Tk's main
    # loop so use run_detached() when available (it spawns its own thread).
    try:
        icon.run_detached()
    except (AttributeError, RuntimeError):
        # Older pystray or unsupported backend — fall back to a thread.
        threading.Thread(target=icon.run, daemon=True).start()
    return icon


def _show_window(app) -> None:
    """Restore + lift the main GUI window from a minimized/withdrawn state."""
    try:
        app.root.deiconify()
        app.root.lift()
        app.root.focus_force()
    except Exception:  # noqa: BLE001 — being defensive at shutdown
        pass


def hide_to_tray(app) -> None:
    """Called by the GUI's WM_DELETE_WINDOW handler. If a tray icon is
    active, withdraw the window instead of destroying it. Otherwise
    fall through to the normal destroy path."""
    icon = getattr(app, "_tray_icon", None)
    if icon is None:
        # No tray running — let normal close happen.
        try:
            app.root.destroy()
        except Exception:  # noqa: BLE001
            pass
        return
    try:
        app.root.withdraw()
    except Exception:  # noqa: BLE001
        pass

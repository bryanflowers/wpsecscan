"""Optional verbose log + crash report writer (--debug flag)."""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path


def _log_dir() -> Path:
    p = Path.home() / ".wpsecscan" / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def configure(debug: bool) -> Path | None:
    """Configure root logging. Returns the log file path if --debug, else None.

    Debug logs go through a rotating file handler (5 MB × 5 backups by default)
    so `~/.wpsecscan/logs/` doesn't grow unbounded across repeated --debug
    runs. Override via WPSECSCAN_LOG_MAX_BYTES + WPSECSCAN_LOG_BACKUP_COUNT.
    """
    if not debug:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
        return None
    # One canonical file name so RotatingFileHandler can manage backups
    # (wpsecscan.log → wpsecscan.log.1 → ... → wpsecscan.log.5).
    path = _log_dir() / "wpsecscan.log"
    try:
        max_bytes = int(os.environ.get("WPSECSCAN_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
    except ValueError:
        max_bytes = 5 * 1024 * 1024
    try:
        backups = int(os.environ.get("WPSECSCAN_LOG_BACKUP_COUNT", "5"))
    except ValueError:
        backups = 5
    handler = logging.handlers.RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[handler, logging.StreamHandler(sys.stderr)],
    )
    logging.info("wpsecscan debug log started (rotating at %d bytes × %d backups)",
                 max_bytes, backups)
    return path


def write_crash_report(exc: BaseException) -> Path:
    """Persist a crash report for support. Returns the path."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = _log_dir() / f"crash-{stamp}.txt"
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    path.write_text(
        f"WPSecScan crash report\nTime:   {datetime.now().isoformat()}\nPython: {sys.version}\nArgv:   {sys.argv}\n\n{tb}",
        encoding="utf-8",
    )
    return path

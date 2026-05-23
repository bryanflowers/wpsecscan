"""Optional verbose log + crash report writer (--debug flag)."""
from __future__ import annotations

import logging
import sys
import traceback
from datetime import datetime
from pathlib import Path


def _log_dir() -> Path:
    p = Path.home() / ".wpsecscan" / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def configure(debug: bool) -> Path | None:
    """Configure root logging. Returns the log file path if --debug, else None."""
    if not debug:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
        return None
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = _log_dir() / f"wpsecscan-{stamp}.log"
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(path, encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )
    logging.info("wpsecscan debug log started")
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

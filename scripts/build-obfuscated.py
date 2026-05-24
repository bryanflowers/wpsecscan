"""Wrap the standard PyInstaller build with optional PyArmor obfuscation.

If `pyarmor` is installed, the wpsecscan/ package is run through it before
PyInstaller bundles. The resulting .exe is harder to decompile but still
totally runnable. The free PyArmor mode is offline / no-key.

If `pyarmor` is NOT installed, this script simply runs the normal build.

Usage:
    pip install 'pyarmor>=9'      # OPTIONAL — for obfuscation
    python scripts/build-obfuscated.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def main() -> int:
    pyarmor_available = False
    try:
        import pyarmor  # type: ignore[import-untyped]  # noqa: F401
        pyarmor_available = True
    except ImportError:
        pass

    if pyarmor_available:
        print("[build] obfuscating wpsecscan/ with PyArmor...")
        obf_out = ROOT / "build" / "obf"
        if obf_out.exists():
            shutil.rmtree(obf_out)
        r = subprocess.run(
            ["pyarmor", "gen", "-O", str(obf_out), "-r", "wpsecscan"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            print(f"[build] pyarmor failed:\n{r.stderr[-800:]}", file=sys.stderr)
            return 1
        # PyInstaller picks up the obfuscated wpsecscan/ first via --paths
        py = sys.executable
        for spec in ("wpsecscan.spec", "wpsecscan-gui.spec"):
            subprocess.run([py, "-m", "PyInstaller", "--noconfirm",
                              "--paths", str(obf_out), spec],
                            cwd=str(ROOT), check=False)
    else:
        print("[build] pyarmor not installed — building plain (open source) binaries")
        py = sys.executable
        for spec in ("wpsecscan.spec", "wpsecscan-gui.spec"):
            r = subprocess.run([py, "-m", "PyInstaller", "--noconfirm", spec],
                                cwd=str(ROOT))
            if r.returncode != 0:
                return r.returncode

    print("[build] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

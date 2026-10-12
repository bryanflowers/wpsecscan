"""WPSecScan package.

``__version__`` prefers the installed distribution metadata so a wheel always
reports its own version; the literal below is the fallback for a bare source
tree and is kept in sync with pyproject.toml by scripts/bump-version.py.
"""
from importlib import metadata as _metadata

_FALLBACK_VERSION = "2.8.5"

try:
    __version__ = _metadata.version("wpsecscan")
except _metadata.PackageNotFoundError:
    __version__ = _FALLBACK_VERSION

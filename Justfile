# v2.8.3 — minimal Justfile.
# Install: `cargo install just` OR `winget install Casey.Just`
# Use: `just test`, `just lint`, `just build`, `just run`

# Default: show available recipes
default:
    @just --list

# Run the full test suite quietly
test:
    .venv/Scripts/python.exe -m pytest tests/ -q --no-header

# Fast test loop (exit on first failure)
test-fast:
    .venv/Scripts/python.exe -m pytest tests/ -q --no-header -x

# Run only the tests matching a pattern
test-k pattern:
    .venv/Scripts/python.exe -m pytest tests/ -q --no-header -k "{{pattern}}"

# Lint (ruff if available; pyflakes fallback)
lint:
    .venv/Scripts/python.exe -m ruff check wpsecscan tests || \
        .venv/Scripts/python.exe -m pyflakes wpsecscan tests || true

# Build sdist + wheel
build:
    rm -rf dist/wpsecscan-*
    .venv/Scripts/python.exe -m build --sdist --wheel --outdir dist/

# Build PyInstaller .exe (CLI + GUI)
build-exe:
    .venv/Scripts/pyinstaller --noconfirm --clean wpsecscan.spec
    .venv/Scripts/pyinstaller --noconfirm --clean wpsecscan-gui.spec

# Run the CLI against the demo target
run target="https://example.com":
    .venv/Scripts/python.exe -m wpsecscan {{target}}

# Open the GUI
gui:
    .venv/Scripts/python.exe -m wpsecscan.gui

# Quick scan (passive only, fast timeout)
quick target:
    .venv/Scripts/python.exe -m wpsecscan {{target}} --timeout 15

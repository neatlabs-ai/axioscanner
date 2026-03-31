#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  AXIOSCAN v1.1 — Linux / macOS Launcher                         ║
# ║  NEATLABS™  |  Security 360, LLC  |  SDVOSB                     ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║  AXIOSCAN v1.1  —  NEATLABS™ / Security 360, LLC    ║"
echo "  ║  Axios Supply Chain Attack Detector & Remediator     ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo ""

# ── Locate Python 3 ──────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3 python3.12 python3.11 python3.10 python3.9 python; do
    if command -v "$cmd" &>/dev/null; then
        VER=$("$cmd" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
        if [ "$VER" -ge 3 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "  [ERROR] Python 3 not found."
    echo ""
    echo "  Install it:"
    echo "    macOS:  brew install python3"
    echo "    Ubuntu: sudo apt install python3 python3-pip"
    echo "    Fedora: sudo dnf install python3"
    echo ""
    exit 1
fi

PY_VER=$("$PYTHON" --version 2>&1)
echo "  Python: $PY_VER"

# ── Check tkinter (required by customtkinter) ─────────────────────────────────
if ! "$PYTHON" -c "import tkinter" &>/dev/null; then
    echo ""
    echo "  [ERROR] tkinter not found."
    echo ""
    echo "  Install it:"
    echo "    Ubuntu/Debian:  sudo apt install python3-tk"
    echo "    Fedora:         sudo dnf install python3-tkinter"
    echo "    macOS:          brew install python-tk"
    echo ""
    exit 1
fi

# ── Install customtkinter if missing ─────────────────────────────────────────
if ! "$PYTHON" -c "import customtkinter" &>/dev/null; then
    echo ""
    echo "  Installing customtkinter..."
    "$PYTHON" -m pip install customtkinter --quiet --user
    echo "  customtkinter installed."
fi

# ── Launch ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN="$SCRIPT_DIR/AXIOSCAN.py"

if [ ! -f "$MAIN" ]; then
    echo "  [ERROR] AXIOSCAN.py not found in: $SCRIPT_DIR"
    exit 1
fi

echo ""
echo "  Launching AXIOSCAN..."
echo ""

"$PYTHON" "$MAIN"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "  [ERROR] AXIOSCAN exited with code $EXIT_CODE"
    echo "  If you see a display error, ensure DISPLAY is set (Linux)"
    echo "  or run: export DISPLAY=:0"
    echo ""
fi

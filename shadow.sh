#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v6 - Intelligence-Driven Bug Bounty Engine
# ═══════════════════════════════════════════════════════════════════════════════
# This is the main entry point.
# Bash is for execution only. Python makes decisions.
# ═══════════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

# Check Python
if ! command -v "$PYTHON" &>/dev/null; then
    echo "[!] Python3 not found. Please install Python 3.8+"
    exit 1
fi

# Check Python version
PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [[ $PY_MAJOR -lt 3 ]] || [[ $PY_MINOR -lt 8 ]]; then
    echo "[!] Python 3.8+ required. Found: $PY_VERSION"
    exit 1
fi

# Run the engine
exec "$PYTHON" -m engine.main "$@"

#!/usr/bin/env bash
set -e

echo "=========================================="
echo "Setting up CRA Scanner Environment (EU CRA)"
echo "=========================================="

# 1. Create Virtual Environment
if [ ! -d ".venv" ]; then
    echo "[1/4] Creating virtual environment (.venv)..."
    python3 -m venv .venv
else
    echo "[1/4] Virtual environment (.venv) already exists."
fi

# 2. Install dependencies
echo "[2/4] Installing dependencies from requirements.txt..."
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt

# 3. Install package
echo "[3/4] Installing crascanner package..."
./.venv/bin/python -m pip install -e . --no-build-isolation

# 4. Verify
echo "[4/4] Verifying installation..."
./.venv/bin/python -c "import crascanner; print('CRA Scanner version:', crascanner.__version__)"

echo "=========================================="
echo "Setup Completed Successfully!"
echo "Run a scan with:"
echo "  ./.venv/bin/crascanner scan <path-to-folder> --output-dir ./output"
echo "=========================================="

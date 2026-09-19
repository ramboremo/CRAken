@echo off
echo ==========================================
echo Setting up CRA Scanner Environment (EU CRA)
echo ==========================================

REM 1. Create Virtual Environment
if not exist ".venv" (
    echo [1/4] Creating virtual environment (.venv)...
    python -m venv .venv
    if errorlevel 1 (
        echo Failed to create virtual environment. Please verify Python 3.10+ is installed.
        exit /b 1
    )
) else (
    echo [1/4] Virtual environment (.venv) already exists.
)

REM 2. Install dependencies
echo [2/4] Installing dependencies from requirements.txt...
call .\.venv\Scripts\python.exe -m pip install --upgrade pip
call .\.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo Failed to install dependencies.
    exit /b 1
)

REM 3. Install package
echo [3/4] Installing crascanner package...
call .\.venv\Scripts\python.exe -m pip install -e . --no-build-isolation
if errorlevel 1 (
    echo Failed to install crascanner.
    exit /b 1
)

REM 4. Verify
echo [4/4] Verifying installation...
call .\.venv\Scripts\python.exe -c "import crascanner; print('CRA Scanner version:', crascanner.__version__)"
if errorlevel 0 (
    echo ==========================================
    echo Setup Completed Successfully!
    echo Run a scan with:
    echo   .\.venv\Scripts\crascanner scan ^<path-to-folder^> --output-dir ./output
    echo ==========================================
)

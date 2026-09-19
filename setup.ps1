# CRA Scanner - Turnkey Setup Script for Windows PowerShell
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Setting up CRA Scanner Environment (EU CRA)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Create Python Virtual Environment
if (-not (Test-Path ".venv")) {
    Write-Host "[1/4] Creating virtual environment (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to create virtual environment. Please verify Python 3.10+ is installed." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[1/4] Virtual environment (.venv) already exists." -ForegroundColor Green
}

# 2. Upgrade pip and install dependencies
Write-Host "[2/4] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install dependencies." -ForegroundColor Red
    exit 1
}

# 3. Install CRAScanner in editable mode
Write-Host "[3/4] Installing crascanner package..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -m pip install -e . --no-build-isolation
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to install crascanner." -ForegroundColor Red
    exit 1
}

# 4. Verification
Write-Host "[4/4] Verifying installation..." -ForegroundColor Yellow
& .\.venv\Scripts\python.exe -c "import crascanner; print('CRA Scanner version:', crascanner.__version__)"
if ($LASTEXITCODE -eq 0) {
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "Setup Completed Successfully!" -ForegroundColor Green
    Write-Host "Run a scan with:" -ForegroundColor White
    Write-Host "  .\.venv\Scripts\crascanner scan <path-to-folder> --output-dir ./output" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Green
} else {
    Write-Host "Verification failed." -ForegroundColor Red
}

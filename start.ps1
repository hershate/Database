# CVE vulnerability database frontend - one-click launcher (Windows PowerShell)
# Usage:  powershell -ExecutionPolicy Bypass -File .\start.ps1
#         or right-click start.ps1 in Explorer -> "Run with PowerShell"

# Switch to the script's directory (project root)
Set-Location -LiteralPath (Split-Path -Parent $MyInvocation.MyCommand.Path)

# UTF-8 console output
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

Write-Host "============================" -ForegroundColor Cyan
Write-Host " CVE vulnerability DB frontend" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan

# ---- Locate Python (prefer py launcher, fall back to python) ----
$py = $null
foreach ($cmd in @('py', 'python')) {
    $ver = $null
    try { $ver = & $cmd --version 2>$null } catch {}
    if ($ver) { $py = $cmd; break }
}
if (-not $py) {
    Write-Host "[ERROR] Python not found. Install Python 3.8+ and add it to PATH." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "Python: $py"

# ---- Virtual environment ----
$venvPython = ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Host "[1/3] Creating virtual environment .venv ..."
    & $py -m venv .venv
    if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Failed to create virtual environment." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
} else {
    Write-Host "[1/3] Virtual environment exists, skipping creation."
}

# ---- Install dependencies ----
Write-Host "[2/3] Installing dependencies ..."
& $venvPython -m pip install -q --upgrade pip
& $venvPython -m pip install -q -r frontend\requirements.txt
if ($LASTEXITCODE -ne 0) { Write-Host "[ERROR] Dependency installation failed." -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }

# ---- Default env vars (only if not already set) ----
if (-not $env:CVE_FRONT_HOST) { $env:CVE_FRONT_HOST = '127.0.0.1' }
if (-not $env:CVE_FRONT_PORT) { $env:CVE_FRONT_PORT = '8765' }
$url = "http://$($env:CVE_FRONT_HOST):$($env:CVE_FRONT_PORT)"

Write-Host "[3/3] Starting server: $url" -ForegroundColor Green
Write-Host "(press Ctrl+C to stop)"
Write-Host ""

# ---- Open browser after a short delay (background) ----
Start-Job -ScriptBlock {
    param($u)
    Start-Sleep -Seconds 2
    try { Start-Process $u } catch {}
} -ArgumentList $url | Out-Null

# ---- Run server in foreground ----
& $venvPython frontend\server.py

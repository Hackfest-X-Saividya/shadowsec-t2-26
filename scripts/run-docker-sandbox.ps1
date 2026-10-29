# Windows version of run-docker-sandbox.sh
#   .\scripts\run-docker-sandbox.ps1           start the dashboard (http://127.0.0.1:8000)
#   .\scripts\run-docker-sandbox.ps1 -Test     run the full scan/attack/fix/re-attack check through real containers
#   .\scripts\run-docker-sandbox.ps1 -Port 8001
# If PowerShell blocks scripts: powershell -ExecutionPolicy Bypass -File scripts\run-docker-sandbox.ps1
param([switch]$Test, [int]$Port = 8000)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$Image = if ($env:LD_SANDBOX_IMAGE) { $env:LD_SANDBOX_IMAGE } else { "zday-protocol-sandbox:latest" }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Write-Error "docker not found. Install Docker Desktop, start it, then run this again." }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error "Docker is installed but not running. Start Docker Desktop, wait until it says running, then run this again." }
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { $null }
if (-not $py) { Write-Error "Python 3.9 or newer not found. Install it from python.org and tick 'Add python.exe to PATH'." }

Write-Host "Building sandbox image $Image ..."
docker build -q -f Dockerfile.sandbox -t $Image .
if ($LASTEXITCODE -ne 0) { Write-Error "Building the sandbox image failed." }

$env:LD_SANDBOX = "docker"
$env:LD_SANDBOX_IMAGE = $Image
if ($Test) { & $py selftest.py } else { & $py server.py $Port }

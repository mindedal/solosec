# install.ps1 - The "One Click" Setup
Write-Host "Installing SoloSec..." -ForegroundColor Cyan

# 1. Check Prerequisites
$missing = @()
if (!(Get-Command python -ErrorAction SilentlyContinue)) { $missing += "Python" }
if (!(Get-Command docker -ErrorAction SilentlyContinue)) { $missing += "Docker" }

if ($missing.Count -gt 0) {
    Write-Error "Missing requirements: $($missing -join ', '). Please install them first."
    exit 1
}

# 2. Check/Install Tools (Using Scoop if available, or Pip/Choco)
Write-Host "[*] Checking dependency tools..."
if (!(Get-Command trivy -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing Trivy..."
    # Attempt Scoop first (cleanest), fall back to Choco
    if (Get-Command scoop -ErrorAction SilentlyContinue) { scoop install trivy }
    else { choco install trivy }
}

if (!(Get-Command semgrep -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing Semgrep (via Pipx)..."
    python -m pip install pipx
    python -m pipx ensurepath
    pipx install semgrep
}

if (!(Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Host "   -> Installing Gitleaks..."
    if (Get-Command scoop -ErrorAction SilentlyContinue) { scoop install gitleaks }
    else { choco install gitleaks }
}

# 3. Add to PATH (Permanently)
$BinPath = "$PSScriptRoot\bin"
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($CurrentPath -notlike "*$BinPath*") {
    Write-Host "[*] Adding '$BinPath' to your User PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$BinPath", "User")
    Write-Host "Added. Restart your terminal to use the command 'solosec'." -ForegroundColor Green
} else {
    Write-Host "'solosec' is already in your PATH." -ForegroundColor Green
}
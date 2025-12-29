<#
.SYNOPSIS
    General Security Auditor for ANY project.
    Run this from the root of the project you want to scan.

.EXAMPLE
    solosec                                  (Code scan only)
    solosec -Url "http://localhost:3000"      (Code + DAST scan)
#>

param (
    [string]$Url = ""
)

# --- CONFIGURATION ---
$ProjectRoot = Get-Location
$ReportDir = "$ProjectRoot\.security_reports"
$FinalReport = "$ProjectRoot\security_audit.json"
$AggregatorScript = "$PSScriptRoot\aggregator.py"
$ConfigLoaderScript = "$PSScriptRoot\config_loader.py"

# --- Load optional .solosec.yaml config (CLI -Url overrides config target_url) ---
$ConfigPath = "$ProjectRoot\.solosec.yaml"
$ExcludeDirs = @()
$ToolTrivy = $true
$ToolSemgrep = $true
$ToolGitleaks = $true
$ToolZap = $true

if (Test-Path $ConfigPath) {
    try {
        $cfgJson = python "$ConfigLoaderScript" "$ProjectRoot" --cli-url "$Url" --format json
        $cfg = $cfgJson | ConvertFrom-Json

        if ($cfg.exclude_dirs) { $ExcludeDirs = @($cfg.exclude_dirs) }
        if ($cfg.tools) {
            if ($null -ne $cfg.tools.trivy) { $ToolTrivy = [bool]$cfg.tools.trivy }
            if ($null -ne $cfg.tools.semgrep) { $ToolSemgrep = [bool]$cfg.tools.semgrep }
            if ($null -ne $cfg.tools.gitleaks) { $ToolGitleaks = [bool]$cfg.tools.gitleaks }
            if ($null -ne $cfg.tools.zap) { $ToolZap = [bool]$cfg.tools.zap }
        }

        # URL may come from config if CLI didn't provide it.
        if ($cfg.url) { $Url = [string]$cfg.url }
        if (-not $ToolZap) { $Url = "" }
    } catch {
        Write-Host "Warning: Failed to parse .solosec.yaml, continuing with defaults." -ForegroundColor DarkYellow
    }
}

Write-Host "STARTING SECURITY AUDIT" -ForegroundColor Cyan
Write-Host "   Target: $ProjectRoot"
if ($Url) { Write-Host "   DAST URL: $Url" }

# 1. Create Hidden Report Directory
if (!(Test-Path $ReportDir)) { 
    New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null 
    # Optional: Add to .gitignore if it exists
    if (Test-Path "$ProjectRoot\.gitignore") {
        if (!(Select-String -Path "$ProjectRoot\.gitignore" -Pattern ".security_reports")) {
            Add-Content -Path "$ProjectRoot\.gitignore" -Value "`n.security_reports/"
        }
    }
}

# 2. TRIVY (Dependencies)
if ($ToolTrivy) {
    Write-Host "`n[1/4] Running Trivy..." -ForegroundColor Yellow
    $skipDirsArg = $null
    if ($ExcludeDirs.Count -gt 0) {
        # Trivy expects a comma-separated list
        $skipDirsArg = ($ExcludeDirs -join ",")
    }
    if ($skipDirsArg) {
        trivy fs . --format json --output "$ReportDir\trivy.json" --quiet --skip-dirs $skipDirsArg
    } else {
        trivy fs . --format json --output "$ReportDir\trivy.json" --quiet
    }
    if ($?) { Write-Host "   -> Done." -ForegroundColor Green }
} else {
    Write-Host "`n[1/4] Skipping Trivy (Disabled in .solosec.yaml)." -ForegroundColor DarkGray
}

# 3. SEMGREP (Code Quality)
if ($ToolSemgrep) {
    Write-Host "[2/4] Running Semgrep..." -ForegroundColor Yellow
    $env:PYTHONUTF8 = 1
    $semgrepArgs = @("scan", "--config=auto", "--json", "--output", "$ReportDir\semgrep.json", "--quiet", ".")
    foreach ($d in $ExcludeDirs) {
        if ($d) { $semgrepArgs += @("--exclude", "$d") }
    }
    semgrep @semgrepArgs
    if ($?) { 
        (Get-Content "$ReportDir\semgrep.json" -Raw) | 
            ConvertFrom-Json | 
            ConvertTo-Json -Depth 100 | 
            Set-Content "$ReportDir\semgrep.json"
            
        Write-Host "   -> Done (and beautified)." -ForegroundColor Green 
    }
} else {
    Write-Host "[2/4] Skipping Semgrep (Disabled in .solosec.yaml)." -ForegroundColor DarkGray
}

# 4. GITLEAKS (Secrets)
if ($ToolGitleaks) {
    Write-Host "[3/4] Running Gitleaks..." -ForegroundColor Yellow
    # Using --no-git ensures it works even if you just downloaded a zip and haven't run 'git init'
    $gitleaksArgs = @("detect", "--source", ".", "--no-git", "--report-path", "$ReportDir\gitleaks.json", "--exit-code", "0")
    foreach ($d in $ExcludeDirs) {
        if ($d) { $gitleaksArgs += @("--exclude-path", "$d") }
    }
    gitleaks @gitleaksArgs
    Write-Host "   -> Done." -ForegroundColor Green
} else {
    Write-Host "[3/4] Skipping Gitleaks (Disabled in .solosec.yaml)." -ForegroundColor DarkGray
}

# 5. ZAP (DAST) - Only runs if URL provided
if ($ToolZap -and $Url) {
    Write-Host "[4/4] Running ZAP..." -ForegroundColor Yellow
    
    # --- AUTO-FIX FOR LOCALHOST ---
    $ZapTarget = $Url
    if ($Url -match "localhost" -or $Url -match "127.0.0.1") {
        Write-Host "      (Detected localhost: Switching to 'host.docker.internal' for Docker compatibility)" -ForegroundColor DarkGray
        $ZapTarget = $Url.Replace("localhost", "host.docker.internal").Replace("127.0.0.1", "host.docker.internal")
    }
    
    Write-Host "      Targeting: $ZapTarget" -ForegroundColor DarkGray

    # Run ZAP Container
    docker run --rm -v "$($ReportDir):/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable `
        zap-full-scan.py -t $ZapTarget -J "zap.json" -r "zap.html" -I
        
    if ($?) { Write-Host "   -> Done." -ForegroundColor Green }
} else {
    Write-Host "[4/4] Skipping ZAP (No URL provided)." -ForegroundColor DarkGray
}

# 6. AGGREGATE
Write-Host "`n[*] Generating Final Report..." -ForegroundColor Cyan
# Call the python script located in the same folder as this PS1 script
python "$AggregatorScript" "$ReportDir" "$FinalReport"

$aggExit = $LASTEXITCODE
if ($aggExit -ne 0) {
    Write-Host "`nAUDIT FAILED!" -ForegroundColor Red
    Write-Host "Report saved to: $FinalReport"
    exit $aggExit
}

Write-Host "`nAUDIT COMPLETE!" -ForegroundColor Magenta
Write-Host "Report saved to: $FinalReport"
<#
.SYNOPSIS
    General Security Auditor for ANY project.
    Run this from the root of the project you want to scan.

.EXAMPLE
    audit-project                                   (Code scan only)
    audit-project -Url "http://localhost:3000"      (Code + DAST scan)
#>

param (
    [string]$Url = ""
)

# --- CONFIGURATION ---
$ProjectRoot = Get-Location
$ReportDir = "$ProjectRoot\.security_reports"
$FinalReport = "$ProjectRoot\security_audit.json"
$AggregatorScript = "$PSScriptRoot\aggregator.py"

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
Write-Host "`n[1/4] Running Trivy..." -ForegroundColor Yellow
trivy fs . --format json --output "$ReportDir\trivy.json" --quiet
if ($?) { Write-Host "   -> Done." -ForegroundColor Green }

# 3. SEMGREP (Code Quality)
Write-Host "[2/4] Running Semgrep..." -ForegroundColor Yellow
$env:PYTHONUTF8 = 1
semgrep scan --config=auto --json --output "$ReportDir\semgrep.json" --quiet .
if ($?) { 
    (Get-Content "$ReportDir\semgrep.json" -Raw) | 
        ConvertFrom-Json | 
        ConvertTo-Json -Depth 100 | 
        Set-Content "$ReportDir\semgrep.json"
        
    Write-Host "   -> Done (and beautified)." -ForegroundColor Green 
}

# 4. GITLEAKS (Secrets)
Write-Host "[3/4] Running Gitleaks..." -ForegroundColor Yellow
# Using --no-git ensures it works even if you just downloaded a zip and haven't run 'git init'
gitleaks detect --source . --no-git --report-path "$ReportDir\gitleaks.json" --exit-code 0
Write-Host "   -> Done." -ForegroundColor Green

# 5. ZAP (DAST) - Only runs if URL provided
if ($Url) {
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

Write-Host "`nAUDIT COMPLETE!" -ForegroundColor Magenta
Write-Host "Report saved to: $FinalReport"
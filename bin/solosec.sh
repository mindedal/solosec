#!/usr/bin/env bash
#
# General Security Auditor for ANY project.
# Run this from the root of the project you want to scan.
#
# Usage:
#   solosec                                  (Code scan only)
#   solosec -u "http://localhost:3000"       (Code + DAST scan)
#

# --- Parse Arguments ---
URL=""
while getopts "u:" opt; do
    case $opt in
        u) URL="$OPTARG" ;;
        *) echo "Usage: $0 [-u <target_url>]"; exit 1 ;;
    esac
done

# --- CONFIGURATION ---
PROJECT_ROOT=$(pwd)
REPORT_DIR="$PROJECT_ROOT/.security_reports"
FINAL_REPORT="$PROJECT_ROOT/security_audit.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGGREGATOR_SCRIPT="$SCRIPT_DIR/aggregator.py"
CONFIG_LOADER_SCRIPT="$SCRIPT_DIR/config_loader.py"

# --- Colors ---
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

echo -e "${CYAN}STARTING SECURITY AUDIT${NC}"
echo "   Target: $PROJECT_ROOT"

# --- Load optional .solosec.yaml config (CLI -u overrides config target_url) ---
CONFIG_PATH="$PROJECT_ROOT/.solosec.yaml"
SOLOSEC_EXCLUDE_DIRS=""
SOLOSEC_TOOL_TRIVY=1
SOLOSEC_TOOL_SEMGREP=1
SOLOSEC_TOOL_GITLEAKS=1
SOLOSEC_TOOL_ZAP=1

if [ -f "$CONFIG_PATH" ]; then
    if command -v python3 &> /dev/null; then
        CONFIG_OUTPUT=$(python3 "$CONFIG_LOADER_SCRIPT" "$PROJECT_ROOT" --cli-url "$URL" --format bash 2>/dev/null) && eval "$CONFIG_OUTPUT"
    else
        CONFIG_OUTPUT=$(python "$CONFIG_LOADER_SCRIPT" "$PROJECT_ROOT" --cli-url "$URL" --format bash 2>/dev/null) && eval "$CONFIG_OUTPUT"
    fi

    # URL may come from config if CLI didn't provide it.
    URL="$SOLOSEC_URL"
fi

if [ -n "$URL" ]; then
    echo "   DAST URL: $URL"
fi

# 1. Create Hidden Report Directory
if [ ! -d "$REPORT_DIR" ]; then
    mkdir -p "$REPORT_DIR"
    # Optional: Add to .gitignore if it exists
    if [ -f "$PROJECT_ROOT/.gitignore" ]; then
        if ! grep -q ".security_reports" "$PROJECT_ROOT/.gitignore"; then
            echo -e "\n.security_reports/" >> "$PROJECT_ROOT/.gitignore"
        fi
    fi
fi

# 2. TRIVY (Dependencies)
if [ "$SOLOSEC_TOOL_TRIVY" = "1" ]; then
    echo -e "\n${YELLOW}[1/4] Running Trivy...${NC}"
    TRIVY_ARGS=(fs . --format json --output "$REPORT_DIR/trivy.json" --quiet)
    if [ -n "$SOLOSEC_EXCLUDE_DIRS" ]; then
        TRIVY_ARGS+=(--skip-dirs "$SOLOSEC_EXCLUDE_DIRS")
    fi
    if trivy "${TRIVY_ARGS[@]}"; then
        echo -e "   ${GREEN}-> Done.${NC}"
    fi
else
    echo -e "\n${GRAY}[1/4] Skipping Trivy (Disabled in .solosec.yaml).${NC}"
fi

# 3. SEMGREP (Code Quality)
if [ "$SOLOSEC_TOOL_SEMGREP" = "1" ]; then
    echo -e "${YELLOW}[2/4] Running Semgrep...${NC}"
    export PYTHONUTF8=1
    SEMGREP_ARGS=(scan --config=auto --json --output "$REPORT_DIR/semgrep.json" --quiet .)
    if [ -n "$SOLOSEC_EXCLUDE_DIRS" ]; then
        IFS=',' read -r -a _EXCLUDES <<< "$SOLOSEC_EXCLUDE_DIRS"
        for d in "${_EXCLUDES[@]}"; do
            if [ -n "$d" ]; then
                SEMGREP_ARGS+=(--exclude "$d")
            fi
        done
    fi

    if semgrep "${SEMGREP_ARGS[@]}" 2>/dev/null; then
        # Beautify JSON using Python (cross-platform)
        python3 -c "
import json
with open('$REPORT_DIR/semgrep.json', 'r') as f:
    data = json.load(f)
with open('$REPORT_DIR/semgrep.json', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null || python -c "
import json
with open('$REPORT_DIR/semgrep.json', 'r') as f:
    data = json.load(f)
with open('$REPORT_DIR/semgrep.json', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null
        echo -e "   ${GREEN}-> Done (and beautified).${NC}"
    fi
else
    echo -e "${GRAY}[2/4] Skipping Semgrep (Disabled in .solosec.yaml).${NC}"
fi

# 4. GITLEAKS (Secrets)
if [ "$SOLOSEC_TOOL_GITLEAKS" = "1" ]; then
    echo -e "${YELLOW}[3/4] Running Gitleaks...${NC}"
    # Using --no-git ensures it works even if you just downloaded a zip and haven't run 'git init'
    GITLEAKS_ARGS=(detect --source . --no-git --report-path "$REPORT_DIR/gitleaks.json" --exit-code 0)
    if [ -n "$SOLOSEC_EXCLUDE_DIRS" ]; then
        IFS=',' read -r -a _EXCLUDES <<< "$SOLOSEC_EXCLUDE_DIRS"
        for d in "${_EXCLUDES[@]}"; do
            if [ -n "$d" ]; then
                GITLEAKS_ARGS+=(--exclude-path "$d")
            fi
        done
    fi
    gitleaks "${GITLEAKS_ARGS[@]}" 2>/dev/null
    echo -e "   ${GREEN}-> Done.${NC}"
else
    echo -e "${GRAY}[3/4] Skipping Gitleaks (Disabled in .solosec.yaml).${NC}"
fi

# 5. ZAP (DAST) - Only runs if URL provided
if [ "$SOLOSEC_TOOL_ZAP" = "1" ] && [ -n "$URL" ]; then
    echo -e "${YELLOW}[4/4] Running ZAP...${NC}"

    # --- AUTO-FIX FOR LOCALHOST ---
    ZAP_TARGET="$URL"
    if echo "$URL" | grep -qE "(localhost|127\\.0\\.0\\.1)"; then
        echo -e "      ${GRAY}(Detected localhost: Switching to 'host.docker.internal' for Docker compatibility)${NC}"
        ZAP_TARGET=$(echo "$URL" | sed 's/localhost/host.docker.internal/g' | sed 's/127\\.0\\.0\\.1/host.docker.internal/g')
    fi

    echo -e "      ${GRAY}Targeting: $ZAP_TARGET${NC}"

    # Run ZAP Container
    if docker run --rm -v "$REPORT_DIR:/zap/wrk/:rw" -t ghcr.io/zaproxy/zaproxy:stable \
        zap-full-scan.py -t "$ZAP_TARGET" -J "zap.json" -r "zap.html" -I; then
        echo -e "   ${GREEN}-> Done.${NC}"
    fi
else
    echo -e "${GRAY}[4/4] Skipping ZAP (No URL provided or disabled).${NC}"
fi

# 6. AGGREGATE
echo -e "\n${CYAN}[*] Generating Final Report...${NC}"
# Call the python script located in the same folder as this script
# Try python3 first (Linux/Mac), fall back to python (Windows/some systems)
set +e
if command -v python3 &> /dev/null; then
    python3 "$AGGREGATOR_SCRIPT" "$REPORT_DIR" "$FINAL_REPORT"
    AGG_EXIT=$?
else
    python "$AGGREGATOR_SCRIPT" "$REPORT_DIR" "$FINAL_REPORT"
    AGG_EXIT=$?
fi
set -e

if [ $AGG_EXIT -ne 0 ]; then
    echo -e "\n${MAGENTA}AUDIT FAILED!${NC}"
    echo "Report saved to: $FINAL_REPORT"
    exit $AGG_EXIT
fi

echo -e "\n${MAGENTA}AUDIT COMPLETE!${NC}"
echo "Report saved to: $FINAL_REPORT"

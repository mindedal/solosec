#!/bin/bash
# install.sh - Setup script for Linux/Mac

# --- Colors ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}Installing SoloSec...${NC}"

# --- Detect OS ---
OS="$(uname -s)"
case "$OS" in
    Linux*)  OS_TYPE="Linux" ;;
    Darwin*) OS_TYPE="Mac" ;;
    *)       echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
esac
echo "   Detected: $OS_TYPE"

# 1. Check Prerequisites
missing=()
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    missing+=("Python")
fi
if ! command -v docker &> /dev/null; then
    missing+=("Docker")
fi

if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${RED}Missing requirements: ${missing[*]}. Please install them first.${NC}"
    exit 1
fi

# 2. Check/Install Tools
echo -e "${CYAN}[*] Checking dependency tools...${NC}"

# --- Install Trivy ---
if ! command -v trivy &> /dev/null; then
    echo -e "${YELLOW}   -> Installing Trivy...${NC}"
    if [ "$OS_TYPE" = "Mac" ]; then
        if command -v brew &> /dev/null; then
            brew install trivy
        else
            echo -e "${RED}   Homebrew not found. Please install Trivy manually: https://trivy.dev${NC}"
        fi
    else
        # Linux - use official install script
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
    fi
else
    echo -e "${GREEN}   -> Trivy already installed.${NC}"
fi

# --- Install Semgrep ---
if ! command -v semgrep &> /dev/null; then
    echo -e "${YELLOW}   -> Installing Semgrep (via pipx)...${NC}"
    if command -v python3 &> /dev/null; then
        python3 -m pip install --user pipx
        python3 -m pipx ensurepath
        python3 -m pipx install semgrep
    else
        python -m pip install --user pipx
        python -m pipx ensurepath
        python -m pipx install semgrep
    fi
else
    echo -e "${GREEN}   -> Semgrep already installed.${NC}"
fi

# --- Install Gitleaks ---
if ! command -v gitleaks &> /dev/null; then
    echo -e "${YELLOW}   -> Installing Gitleaks...${NC}"
    if [ "$OS_TYPE" = "Mac" ]; then
        if command -v brew &> /dev/null; then
            brew install gitleaks
        else
            echo -e "${RED}   Homebrew not found. Please install Gitleaks manually: https://github.com/gitleaks/gitleaks${NC}"
        fi
    else
        # Linux - download from GitHub releases
        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks
    fi
else
    echo -e "${GREEN}   -> Gitleaks already installed.${NC}"
fi

# 3. Add to PATH
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$SCRIPT_DIR/bin"

# Determine shell config file
if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ] || [ "$SHELL" = "/bin/bash" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

# Check if already in PATH
if [[ ":$PATH:" != *":$BIN_PATH:"* ]]; then
    echo -e "${CYAN}[*] Adding '$BIN_PATH' to your PATH...${NC}"
    
    # Add to shell config
    echo "" >> "$SHELL_RC"
    echo "# SoloSec" >> "$SHELL_RC"
    echo "export PATH=\"\$PATH:$BIN_PATH\"" >> "$SHELL_RC"
    
    echo -e "${GREEN}Added to $SHELL_RC${NC}"
    echo -e "${YELLOW}Restart your terminal or run: source $SHELL_RC${NC}"
else
    echo -e "${GREEN}'solosec' is already in your PATH.${NC}"
fi

# 4. Make scripts executable
chmod +x "$BIN_PATH/solosec.sh" 2>/dev/null || true
chmod +x "$BIN_PATH/solosec" 2>/dev/null || true

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "Run ${CYAN}solosec${NC} from any project directory to start a security audit."

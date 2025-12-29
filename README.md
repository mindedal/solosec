SoloSec
The lazy developer's security suite.

Automated DevSecOps wrapper for Windows. Runs the industry standard tools in one click.

Tools Included:

- Trivy (Dependencies & IaC)
- Semgrep (SAST / Code Quality)
- Gitleaks (Secret Detection)
- OWASP ZAP (DAST / Hacking)

Installation
PowerShell

git clone https://github.com/YOUR_USERNAME/solosec.git
cd solosec
.\install.ps1
Usage
Go to any project folder and run:

PowerShell

# Scan code only

solosec
Scan code + Attack running app
solosec -Url http://localhost:3000

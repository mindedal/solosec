# SoloSec

**Security automation for development teams.**

Automated DevSecOps wrapper for Windows, macOS, and Linux. Runs industry-standard security tools with a single command.

## Tools Included

- **Trivy** - Dependencies & IaC scanning
- **Semgrep** - SAST / Code Quality analysis
- **Gitleaks** - Secret Detection
- **OWASP ZAP** - DAST / Dynamic Application Security Testing

---

## Installation

### PowerShell

```powershell
git clone https://github.com/mindedal/solosec.git
cd solosec
.\install.ps1
```

### Docker (containerized execution)

If you already have Docker, you can run SoloSec without installing Python/Trivy/Semgrep/Gitleaks on your machine.

Build the image:

```bash
docker build -t myname/solosec .
```

Run it against the current folder (report is written to your project as `security_audit.json`):

```bash
docker run --rm -v "$(pwd):/src" myname/solosec
```

Optional DAST (OWASP ZAP) requires Docker access from inside the container (mount the Docker socket):

```bash
docker run --rm \
    -v "$(pwd):/src" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    myname/solosec -u "http://host.docker.internal:3000"
```

**Notes:**

- On Linux, DAST against a host-only service can be more complex. Consider scanning a service running in Docker and use its container/network address, or expose it and target your host IP.
- If file ownership is inconvenient on Linux, you can add `--user "$(id -u):$(id -g)"` to the `docker run` command.

---

## Usage

Go to any project folder and run:

```powershell
# Scan code only
solosec

# Scan code + run DAST against a running app
solosec -Url http://localhost:3000
```

---

## CI/CD (GitHub Actions)

GitHub Actions (and most CI systems) decide whether a job is **Pass (green)** or **Fail (red)** based on the **process exit code**:

- Exit code `0` → pass
- Exit code `!= 0` → fail

SoloSec is designed to have “teeth” in CI:

- The aggregator exits **non-zero** if it finds any **HIGH** or **CRITICAL** issues.
- The `solosec` runner scripts propagate that exit code to the shell.

This repo includes a ready-to-use workflow at `.github/workflows/solosec.yml` that:

1. Builds the included `Dockerfile` (so Trivy/Semgrep/Gitleaks are available)
2. Runs `solosec` against your repository
3. Uploads `security_audit.json` and `.security_reports/` as build artifacts

If you want to run ZAP (DAST) in CI, trigger the workflow manually and pass the `url` input.

### Use SoloSec from other repositories

This repo also ships as a reusable GitHub Action (composite action). In another repository, add a workflow step like:

```yaml
- name: SoloSec scan
  uses: mindedal/solosec@v1
  with:
    # Optional: enables OWASP ZAP (requires docker socket access)
    # url: http://host.docker.internal:3000
    upload-artifact: true
    artifact-name: solosec-report
```

**Important:** for stable usage, create a tag/release like `v1` in this repo and update it when you publish compatible changes.

---

## Config File (.solosec.yaml)

You can configure SoloSec per-repository by adding a `.solosec.yaml` file at the project root.

Example:

```yaml
target_url: "http://localhost:3000"
exclude_dirs:
  - "tests/"
  - "legacy/"
tools:
  zap: true
  semgrep: true
  gitleaks: false
  trivy: true
```

**Notes:**

- `target_url` enables OWASP ZAP DAST (unless `tools.zap: false`).
- `exclude_dirs` is applied to Trivy (`--skip-dirs`), Semgrep (`--exclude`), and Gitleaks (`--exclude-path`).
- CLI flags override config (e.g., `solosec -Url ...` wins over `target_url`).

---

## License

MIT License — see `LICENSE`.

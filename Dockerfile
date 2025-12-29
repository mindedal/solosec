# SoloSec - Docker image (containerized runner)
# Build:
#   docker build -t solosec:local .
# Run:
#   docker run --rm -v "$(pwd):/src" solosec:local
#   docker run --rm -v "$(pwd):/src" solosec:local -u "http://host.docker.internal:3000"

FROM python:3.11-slim-bookworm

# Optional build args for reproducible builds
ARG TRIVY_VERSION=
ARG GITLEAKS_VERSION=

ENV PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Base utilities + docker CLI (for optional ZAP runs)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      git \
      gzip \
      tar \
      docker.io \
 && rm -rf /var/lib/apt/lists/*

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin ${TRIVY_VERSION}

# Semgrep + pretty terminal output
RUN python -m pip install --upgrade pip \
 && python -m pip install semgrep rich

# Gitleaks
RUN set -euo pipefail; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch="linux_x64" ;; \
      arm64) gl_arch="linux_arm64" ;; \
      *) echo "Unsupported architecture for gitleaks: $arch" >&2; exit 1 ;; \
    esac; \
    if [ -z "${GITLEAKS_VERSION}" ]; then \
      GITLEAKS_VERSION="$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | head -n 1 | sed -E 's/.*"v?([^\"]+)\".*/\1/')"; \
    fi; \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${gl_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    chmod +x /usr/local/bin/gitleaks

# Copy SoloSec scripts into the image
WORKDIR /opt/solosec
COPY bin/ ./bin/

RUN chmod +x ./bin/solosec ./bin/solosec.sh || true \
 && ln -sf /opt/solosec/bin/solosec /usr/local/bin/solosec

# The scanned project is expected to be bind-mounted at /src
WORKDIR /src

ENTRYPOINT ["solosec"]

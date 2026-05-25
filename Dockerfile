# ============================================
# SentinelAI — Root Dockerfile (Coolify / CI)
# ============================================
# This Dockerfile is intentionally placed at the repo root so that
# Coolify (and other deployment platforms) can discover it automatically.
# It delegates the full build to backend/Dockerfile via a COPY of the
# backend directory into a clean context.
#
# Build context  : repo root  (Coolify default)
# Application dir: /app       (inside the image)
# ============================================

FROM python:3.11-slim-bookworm

LABEL maintainer="SentinelAI Team"
LABEL description="SentinelAI Security Scanning Agent"

# Prevent Python from writing pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONFAULTHANDLER=1

# Install system dependencies and all security scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    gcc g++ make cmake \
    # Git
    git \
    # Network tools
    nmap masscan dnsutils net-tools iputils-ping curl wget \
    # SSL/TLS tools
    openssl libssl-dev \
    # Python dev
    python3-dev python3-pip \
    # Other utilities
    unzip zip p7zip-full file \
    # For PDF generation
    weasyprint libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    # jq for JSON parsing
    jq \
    # Ruby for Ruby tools
    ruby ruby-dev \
    # Node.js for JS tools
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Install modern Go (Go 1.23.2) manually as Debian's package is too old
RUN wget -q https://go.dev/dl/go1.23.2.linux-amd64.tar.gz -O /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz

# ── Go-based security tools ────────────────────────────────────────────────
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p $GOPATH


RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && nuclei -update-templates
RUN go install -v github.com/owasp-amass/amass/v4/...@master

# ── Python security tools ───────────────────────────────────────────────────
RUN pip install --no-cache-dir \
    sslyze \
    semgrep \
    bandit \
    safety \
    trufflehog3 \
    detect-secrets \
    wapiti3 \
    checkov

# ── External binary tools ───────────────────────────────────────────────────
# Gitleaks
RUN curl -sSL https://github.com/zricethezav/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.48.0

# Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin v0.73.0

# OWASP Dependency-Check
RUN wget -q https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.7/dependency-check-9.0.7-release.zip \
    -O /tmp/dc.zip \
    && unzip -q /tmp/dc.zip -d /opt/dependency-check \
    && rm /tmp/dc.zip \
    && chmod +x /opt/dependency-check/bin/dependency-check.sh
ENV DEPENDENCY_CHECK_HOME=/opt/dependency-check

# testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
ENV TESTSSL_HOME=/opt/testssl.sh

# Nikto
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Brakeman (Ruby)
RUN gem install brakeman

# ESLint security plugin
RUN npm install -g eslint eslint-plugin-security

# ── Application ─────────────────────────────────────────────────────────────
WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source from the backend subdirectory
COPY backend/ .

# Create runtime directories
RUN mkdir -p /tmp/scan_workspace /app/reports /app/logs \
    && chmod -R 755 /app /tmp/scan_workspace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--loop", "uvloop"]

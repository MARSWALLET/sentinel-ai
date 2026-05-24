# SentinelAI - AI-Powered Security Scanning Agent

```
  ____            _   _ _       _       ___    ____
 / ___|  ___  ___| |_(_) | __ _| |     |_ _|  / ___|
 \___ \ / _ \/ __| __| | |/ _` | |      | |  | |
  ___) |  __/\__ \ |_| | | (_| | | ___  | |  | |___
 |____/ \___||___/\__|_|_|\__,_|_| ( ) |___|  \____|
                                   |/
```

SentinelAI is a production-grade, autonomous security scanning agent that audits web applications, APIs, backends, and codebases for vulnerabilities, misconfigurations, secrets, and security flaws. It orchestrates 15+ industry-leading open-source security tools and uses DeepSeek (or any user-supplied LLM) as the AI brain to interpret results, correlate findings, generate remediation advice, and produce professional reports.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Applications                       │
│  (Web UI / CI-CD / CLI / curl)                                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │ REST API / WebSocket
┌───────────────────────────▼─────────────────────────────────────┐
│                    FastAPI Application (api)                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                │
│  │ Auth Router │ │Scan Router  │ │Report Router│                │
│  └─────────────┘ └─────────────┘ └─────────────┘                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                │
│  │Findings Rtr │ │Settings Rtr │ │WebSocket    │                │
│  └─────────────┘ └─────────────┘ └─────────────┘                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                   Celery Task Queue (Redis)                      │
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│   │   Worker    │    │   Worker    │    │   Worker    │         │
│   │  (scan #1)  │    │  (scan #2)  │    │  (scan #3)  │  ← Scale│
│   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
└──────────┼──────────────────┼──────────────────┼────────────────┘
           │                  │                  │
┌──────────▼──────────────────▼──────────────────▼────────────────┐
│                     Scanner Modules                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │  Recon   │ │   Web    │ │  SSL/TLS │ │   SAST   │           │
│  │  Scanner │ │ Scanner  │ │ Scanner  │ │ Scanner  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐           │
│  │ Secrets  │ │    Deps  │ │   API    │ │  Infra   │           │
│  │ Scanner  │ │ Scanner  │ │ Scanner  │ │ Scanner  │           │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                       │
│  │ Network  │ │  AI Code  │ │ Report   │                       │
│  │ Scanner  │ │  Reviewer │ │ Generator│                       │
│  └──────────┘ └──────────┘ └──────────┘                       │
└─────────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Data Layer: PostgreSQL  │  Cache: Redis  │  ZAP Proxy          │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **10 Scanning Modules**: Reconnaissance, Web Application, SSL/TLS, SAST, Secrets Scanning, Dependency Analysis, API Security, Infrastructure, Network, and AI-Powered Code Review
- **5 Input Modes**: URL, GitHub Repo, Code Upload, Raw Code Paste, API Endpoint
- **15+ Security Tools**: Nmap, OWASP ZAP, Nuclei, Semgrep, TruffleHog, Trivy, and more
- **AI-Powered Analysis**: DeepSeek LLM correlates findings, generates remediation advice, and produces executive summaries
- **Real-Time Updates**: WebSocket live progress streaming during scans
- **Multi-Tenant**: Organization-based data isolation
- **CI/CD Ready**: GitHub Actions, GitLab CI, and Jenkins integrations
- **REST API**: Full OpenAPI documentation, async task processing
- **Professional Reports**: JSON, HTML, and PDF output formats

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 8GB+ RAM recommended
- Linux/macOS/WSL2

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd sentinel-ai
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env and set your LLM API key and secrets
   ```

3. **Generate encryption keys:**
   ```bash
   # Generate JWT secret
   openssl rand -hex 32
   
   # Generate AES encryption key
   openssl rand -hex 16
   ```

4. **Start SentinelAI:**
   ```bash
   chmod +x start.sh
   ./start.sh up
   ```

5. **Access the services:**
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/api/health
   - Flower Dashboard: http://localhost:5555
   - ZAP Proxy: http://localhost:8090

### API Usage Examples

#### Register an Organization
```bash
curl -X POST "http://localhost:8000/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "Acme Corp",
    "email": "admin@acme.com",
    "password": "secure_password_123"
  }'
```

#### Login
```bash
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@acme.com",
    "password": "secure_password_123"
  }'
```

#### Start a URL Scan
```bash
curl -X POST "http://localhost:8000/api/scans/url" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "modules": ["recon", "web", "ssl"]
  }'
```

#### Start a GitHub Repo Scan
```bash
curl -X POST "http://localhost:8000/api/scans/github" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/owner/repo",
    "branch": "main",
    "github_token": "ghp_xxxxxxxx"
  }'
```

#### Get Scan Status & Results
```bash
# Get scan details
curl "http://localhost:8000/api/scans/<scan_id>" \
  -H "Authorization: Bearer <token>"

# Get findings
curl "http://localhost:8000/api/scans/<scan_id>/findings" \
  -H "Authorization: Bearer <token>"

# Download HTML report
curl "http://localhost:8000/api/scans/<scan_id>/report/html" \
  -H "Authorization: Bearer <token>" \
  --output report.html
```

#### WebSocket Live Progress
```javascript
const ws = new WebSocket(`ws://localhost:8000/api/scans/${scanId}/live?token=${jwtToken}`);
ws.onmessage = (event) => {
    const progress = JSON.parse(event.data);
    console.log(`Module: ${progress.module} - ${progress.status} - ${progress.percentage}%`);
};
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_USER` | PostgreSQL username | sentinelai |
| `POSTGRES_PASSWORD` | PostgreSQL password | - |
| `POSTGRES_DB` | PostgreSQL database | sentinelai |
| `DATABASE_URL` | Full database connection URL | - |
| `REDIS_PASSWORD` | Redis password | - |
| `REDIS_URL` | Redis connection URL | - |
| `CELERY_BROKER_URL` | Celery broker (Redis) | - |
| `CELERY_RESULT_BACKEND` | Celery result backend (Redis) | - |
| `SECRET_KEY` | JWT signing secret (hex 64 chars) | - |
| `ENCRYPTION_KEY` | AES encryption key (hex 32 chars) | - |
| `LLM_PROVIDER` | LLM provider (deepseek/openai/anthropic/groq/ollama) | deepseek |
| `LLM_API_KEY` | LLM API key | - |
| `LLM_MODEL` | LLM model name | deepseek-chat |
| `LLM_BASE_URL` | Custom LLM base URL (optional) | - |
| `ZAP_API_KEY` | OWASP ZAP API key | - |
| `API_PORT` | API server port | 8000 |
| `LOG_LEVEL` | Logging level (DEBUG/INFO/WARNING/ERROR) | INFO |
| `MAX_SCAN_DURATION` | Maximum scan duration in seconds | 3600 |
| `MODULE_TIMEOUT` | Per-module timeout in seconds | 600 |
| `SELF_HOSTED_MODE` | Allow internal IP scanning | false |
| `ALLOWED_INTERNAL_IPS` | Comma-separated allowed CIDR ranges | 10.0.0.0/8,... |

## Scaling Workers

To handle more concurrent scans, scale the Celery workers:

```bash
# Scale to 5 workers
./start.sh scale 5

# Or with docker compose directly
docker compose up -d --scale worker=5
```

## Adding a New Scanner Module

1. Create a new file in `backend/scanner/` (e.g., `my_scanner.py`)
2. Inherit from `BaseScanner` class
3. Implement the `run()` method
4. Register in `orchestrator.py` module mapping

Example:
```python
from scanner.base_scanner import BaseScanner

class MyScanner(BaseScanner):
    def __init__(self, target, config):
        super().__init__(target, config)
        self.module_name = "my_module"
    
    async def run(self):
        findings = []
        # Your scanning logic here
        # Use self.run_tool() to execute CLI tools
        return findings
```

## Scanning Modules Detail

| Module | Tools | Input Types |
|--------|-------|-------------|
| Reconnaissance | Nmap, Amass, Subfinder, httpx, WhatWeb | URL |
| Web Application | OWASP ZAP, Nikto, Nuclei, Wapiti | URL |
| SSL/TLS | testssl.sh, SSLyze | URL |
| SAST | Semgrep, Bandit, ESLint, Brakeman, SpotBugs, Gosec | GitHub, Upload, Paste |
| Secrets | TruffleHog, Gitleaks | GitHub, Upload |
| Dependencies | Trivy, Grype, OWASP Dependency-Check | GitHub, Upload |
| API Security | Nuclei API, Custom Fuzzer, ZAP API | API Endpoint |
| Infrastructure | Checkov, Trivy Config | GitHub, Upload |
| Network | Nmap, Masscan | URL |
| AI Code Review | DeepSeek LLM | GitHub, Upload, Paste |

## Compliance Mapping

SentinelAI checks for compliance requirements across multiple frameworks:

- **GDPR**: Data protection, encryption, access controls
- **PCI-DSS**: Secure coding, vulnerability scanning, access restrictions
- **HIPAA**: Audit logging, encryption, authentication
- **SOC2**: Security monitoring, incident response, change management

## CI/CD Integration

Ready-made integration templates are provided in `ci-templates/`:

- **GitHub Actions**: `.github/workflows/sentinelai.yml`
- **GitLab CI**: `.gitlab-ci.yml`
- **Jenkins**: `Jenkinsfile`

All integrations support `--fail-on` severity thresholds and automatic PR comments.

## License

This project is provided as-is for security auditing and educational purposes. Ensure you have proper authorization before scanning any systems you do not own.

## Security Disclaimer

SentinelAI is a powerful security tool. Only use it on systems you own or have explicit written permission to test. Unauthorized scanning may violate laws in your jurisdiction.

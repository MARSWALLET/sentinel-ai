# ============================================
# SentinelAI - Configuration
# ============================================
"""
Application configuration loaded from environment variables.
Uses Pydantic Settings for validation and type safety.
"""

import os
import secrets
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field, validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # --- Application ---
    APP_NAME: str = "SentinelAI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    
    # --- Security ---
    SECRET_KEY: str = Field(..., min_length=32, description="JWT signing secret (hex 64 chars)")
    ENCRYPTION_KEY: str = Field(..., min_length=16, description="AES encryption key (hex 32 chars)")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # --- Database ---
    DATABASE_URL: str = Field(..., description="PostgreSQL connection URL")
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # --- Redis ---
    REDIS_URL: str = Field(..., description="Redis connection URL")
    
    # --- Celery ---
    CELERY_BROKER_URL: str = Field(..., description="Celery broker URL (Redis)")
    CELERY_RESULT_BACKEND: str = Field(..., description="Celery result backend URL")
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_ACCEPT_CONTENT: List[str] = ["json"]
    CELERY_RESULT_SERIALIZER: str = "json"
    CELERY_TIMEZONE: str = "UTC"
    CELERY_ENABLE_UTC: bool = True
    CELERY_TASK_TRACK_STARTED: bool = True
    CELERY_TASK_TIME_LIMIT: int = 3600  # 1 hour
    
    # --- LLM Configuration ---
    LLM_PROVIDER: str = Field(default="deepseek", pattern=r"^(deepseek|openai|anthropic|groq|ollama)$")
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "deepseek-chat"
    LLM_BASE_URL: Optional[str] = None
    LLM_TIMEOUT: int = 120
    LLM_MAX_RETRIES: int = 3
    LLM_RETRY_DELAY: float = 2.0
    LLM_MAX_TOKENS: int = 4096
    LLM_TEMPERATURE: float = 0.1
    
    # --- OWASP ZAP ---
    ZAP_API_URL: str = "http://zap:8090"
    ZAP_API_KEY: str = ""
    
    # --- Scan Settings ---
    MAX_SCAN_DURATION: int = 3600  # 1 hour
    MODULE_TIMEOUT: int = 600  # 10 minutes
    MODULE_MAX_RETRIES: int = 2
    MAX_WORKSPACE_SIZE_MB: int = 1024  # 1GB
    MAX_FILE_SIZE_MB: int = 50
    
    # --- Self-Hosted Mode ---
    SELF_HOSTED_MODE: bool = False
    ALLOWED_INTERNAL_IPS: List[str] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    
    # --- File Storage ---
    SCAN_WORKSPACE_DIR: str = "/tmp/scan_workspace"
    REPORTS_DIR: str = "/app/reports"
    LOGS_DIR: str = "/app/logs"
    
    # --- Rate Limiting ---
    RATE_LIMIT_PER_MINUTE: int = 60
    SCAN_RATE_LIMIT_PER_HOUR: int = 10
    
    # --- Paths to Security Tools ---
    NMAP_PATH: str = "/usr/bin/nmap"
    MASSCAN_PATH: str = "/usr/bin/masscan"
    AMASS_PATH: str = "/go/bin/amass"
    SUBFINDER_PATH: str = "/go/bin/subfinder"
    HTTPX_PATH: str = "/go/bin/httpx"
    NUCLEI_PATH: str = "/go/bin/nuclei"
    NIKTO_PATH: str = "/usr/local/bin/nikto"
    WAPITI_PATH: str = "/usr/local/bin/wapiti"
    TESTSSL_PATH: str = "/opt/testssl.sh/testssl.sh"
    SSLYZE_PATH: str = "/usr/local/bin/sslyze"
    SEMGREP_PATH: str = "/usr/local/bin/semgrep"
    BANDIT_PATH: str = "/usr/local/bin/bandit"
    ESLINT_PATH: str = "/usr/local/bin/eslint"
    BRAKEMAN_PATH: str = "/usr/local/bin/brakeman"
    SPOTBUGS_PATH: str = "/usr/local/bin/spotbugs"
    PHPSTAN_PATH: str = "/usr/local/bin/phpstan"
    GOSEC_PATH: str = "/usr/local/bin/gosec"
    CHECKOV_PATH: str = "/usr/local/bin/checkov"
    TRUFFLEHOG_PATH: str = "/usr/local/bin/trufflehog"
    GITLEAKS_PATH: str = "/usr/local/bin/gitleaks"
    TRIVY_PATH: str = "/usr/local/bin/trivy"
    GRYPE_PATH: str = "/usr/local/bin/grype"
    DEPENDENCY_CHECK_PATH: str = "/opt/dependency-check/bin/dependency-check.sh"
    
    @validator("ALLOWED_INTERNAL_IPS", pre=True)
    def parse_allowed_ips(cls, v):
        """Parse comma-separated IPs string into a list."""
        if isinstance(v, str):
            return [ip.strip() for ip in v.split(",") if ip.strip()]
        if isinstance(v, list):
            return v
        return []
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings


# Tool path mapping for scanner modules
TOOL_PATHS = {
    "nmap": settings.NMAP_PATH,
    "masscan": settings.MASSCAN_PATH,
    "amass": settings.AMASS_PATH,
    "subfinder": settings.SUBFINDER_PATH,
    "httpx": settings.HTTPX_PATH,
    "nuclei": settings.NUCLEI_PATH,
    "nikto": settings.NIKTO_PATH,
    "wapiti": settings.WAPITI_PATH,
    "testssl": settings.TESTSSL_PATH,
    "sslyze": settings.SSLYZE_PATH,
    "semgrep": settings.SEMGREP_PATH,
    "bandit": settings.BANDIT_PATH,
    "eslint": settings.ESLINT_PATH,
    "brakeman": settings.BRAKEMAN_PATH,
    "spotbugs": settings.SPOTBUGS_PATH,
    "phpstan": settings.PHPSTAN_PATH,
    "gosec": settings.GOSEC_PATH,
    "checkov": settings.CHECKOV_PATH,
    "trufflehog": settings.TRUFFLEHOG_PATH,
    "gitleaks": settings.GITLEAKS_PATH,
    "trivy": settings.TRIVY_PATH,
    "grype": settings.GRYPE_PATH,
    "dependency_check": settings.DEPENDENCY_CHECK_PATH,
    "whatweb": "/usr/bin/whatweb",
}
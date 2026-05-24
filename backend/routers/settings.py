# ============================================
# SentinelAI - Settings Router
# ============================================
"""
Settings management endpoints:
- GET /api/settings/llm — get LLM configuration
- PUT /api/settings/llm — update LLM configuration
- GET /api/settings/integrations — get CI/CD webhook config
- PUT /api/settings/integrations — update integrations
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings as app_settings
from database import get_db
from models.finding import LLMConfig
from models.organization import OrgSettings
from models.user import User
from routers.auth import get_current_user
from utils.crypto_utils import encrypt_text, decrypt_text

logger = logging.getLogger(__name__)
router = APIRouter()


# --- Pydantic Schemas ---

class LLMConfigRequest(BaseModel):
    provider: str = Field(..., pattern=r"^(deepseek|openai|anthropic|groq|ollama)$")
    model: str = Field(..., min_length=1)
    api_key: str = Field(..., min_length=1)
    base_url: Optional[str] = None
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1, le=8192)
    enable_code_review: bool = True
    enable_correlation: bool = True
    enable_remediation: bool = True


class LLMConfigResponse(BaseModel):
    id: str
    provider: str
    model: str
    base_url: Optional[str]
    temperature: float
    max_tokens: int
    enable_code_review: bool
    enable_correlation: bool
    enable_remediation: bool
    created_at: str


class IntegrationConfig(BaseModel):
    github_webhook_url: Optional[str] = None
    github_webhook_secret: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    email_notifications: bool = True
    notify_on_severity: str = Field(default="high", pattern=r"^(critical|high|medium|low|all|none)$")


class IntegrationResponse(BaseModel):
    github_webhook_url: Optional[str]
    github_webhook_secret_configured: bool
    slack_webhook_url: Optional[str]
    email_notifications: bool
    notify_on_severity: str


# --- Endpoints ---

@router.get("/llm", response_model=LLMConfigResponse)
async def get_llm_config(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get the organization's LLM configuration.
    API keys are not returned for security.
    """
    result = await db.execute(
        select(LLMConfig).where(LLMConfig.org_id == current_user.org_id)
    )
    config = result.scalar_one_or_none()
    
    if not config:
        # Return default config
        return LLMConfigResponse(
            id="default",
            provider=app_settings.LLM_PROVIDER,
            model=app_settings.LLM_MODEL,
            base_url=app_settings.LLM_BASE_URL,
            temperature=0.1,
            max_tokens=4096,
            enable_code_review=True,
            enable_correlation=True,
            enable_remediation=True,
            created_at="",
        )
    
    return LLMConfigResponse(
        id=config.id,
        provider=config.provider,
        model=config.model,
        base_url=config.base_url,
        temperature=config.temperature or 0.1,
        max_tokens=config.max_tokens or 4096,
        enable_code_review=config.enable_code_review,
        enable_correlation=config.enable_correlation,
        enable_remediation=config.enable_remediation,
        created_at=config.created_at.isoformat() if config.created_at else "",
    )


@router.put("/llm", response_model=LLMConfigResponse)
async def update_llm_config(
    request: LLMConfigRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update the organization's LLM configuration.
    Encrypts the API key before storing.
    """
    # Encrypt API key
    encrypted_key = encrypt_text(request.api_key, app_settings.ENCRYPTION_KEY)
    
    result = await db.execute(
        select(LLMConfig).where(LLMConfig.org_id == current_user.org_id)
    )
    config = result.scalar_one_or_none()
    
    if config:
        # Update existing
        config.provider = request.provider
        config.model = request.model
        config.api_key_encrypted = encrypted_key
        config.base_url = request.base_url
        config.temperature = request.temperature
        config.max_tokens = request.max_tokens
        config.enable_code_review = request.enable_code_review
        config.enable_correlation = request.enable_correlation
        config.enable_remediation = request.enable_remediation
    else:
        # Create new
        config = LLMConfig(
            org_id=current_user.org_id,
            provider=request.provider,
            model=request.model,
            api_key_encrypted=encrypted_key,
            base_url=request.base_url,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            enable_code_review=request.enable_code_review,
            enable_correlation=request.enable_correlation,
            enable_remediation=request.enable_remediation,
        )
        db.add(config)
    
    await db.commit()
    await db.refresh(config)
    
    logger.info(f"LLM config updated for org {current_user.org_id}: provider={request.provider}, model={request.model}")
    
    return LLMConfigResponse(
        id=config.id,
        provider=config.provider,
        model=config.model,
        base_url=config.base_url,
        temperature=config.temperature or 0.1,
        max_tokens=config.max_tokens or 4096,
        enable_code_review=config.enable_code_review,
        enable_correlation=config.enable_correlation,
        enable_remediation=config.enable_remediation,
        created_at=config.created_at.isoformat() if config.created_at else "",
    )


@router.get("/integrations", response_model=IntegrationResponse)
async def get_integrations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get CI/CD and notification integration settings.
    """
    # Bug #28 fixed: load from OrgSettings table instead of returning empty defaults.
    result = await db.execute(
        select(OrgSettings).where(OrgSettings.org_id == current_user.org_id)
    )
    org_settings = result.scalar_one_or_none()
    cfg = org_settings.integration_config if org_settings else {}
    
    return IntegrationResponse(
        github_webhook_url=cfg.get("github_webhook_url"),
        github_webhook_secret_configured=bool(cfg.get("github_webhook_secret_configured")),
        slack_webhook_url=cfg.get("slack_webhook_url"),
        email_notifications=cfg.get("email_notifications", True),
        notify_on_severity=cfg.get("notify_on_severity", "high"),
    )


@router.put("/integrations", response_model=IntegrationResponse)
async def update_integrations(
    request: IntegrationConfig,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update CI/CD and notification integration settings.
    """
    # Bug #28 fixed: actually persist the settings. Previously this endpoint
    # logged the update, then returned the request body without saving anything.
    result = await db.execute(
        select(OrgSettings).where(OrgSettings.org_id == current_user.org_id)
    )
    org_settings = result.scalar_one_or_none()
    
    # Build the config dict. We never store the raw webhook secret — only a flag.
    new_cfg = {
        "github_webhook_url": request.github_webhook_url,
        "github_webhook_secret_configured": bool(request.github_webhook_secret),
        "slack_webhook_url": request.slack_webhook_url,
        "email_notifications": request.email_notifications,
        "notify_on_severity": request.notify_on_severity,
    }
    
    # Encrypt and store the webhook secret separately if provided
    if request.github_webhook_secret:
        new_cfg["github_webhook_secret_enc"] = encrypt_text(
            request.github_webhook_secret, app_settings.ENCRYPTION_KEY
        )
    elif org_settings:
        # Preserve existing encrypted secret if not being updated
        new_cfg["github_webhook_secret_enc"] = org_settings.integration_config.get(
            "github_webhook_secret_enc"
        )
    
    if org_settings:
        org_settings.integration_config = new_cfg
    else:
        org_settings = OrgSettings(
            org_id=current_user.org_id,
            integration_config=new_cfg,
        )
        db.add(org_settings)
    
    await db.commit()
    logger.info(f"Integration settings persisted for org {current_user.org_id}")
    
    return IntegrationResponse(
        github_webhook_url=request.github_webhook_url,
        github_webhook_secret_configured=bool(request.github_webhook_secret),
        slack_webhook_url=request.slack_webhook_url,
        email_notifications=request.email_notifications,
        notify_on_severity=request.notify_on_severity,
    )
# ============================================
# SentinelAI - Organization Model
# ============================================
"""
Organization model for multi-tenant data isolation.
Each scan, user, and finding belongs to an organization.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Enum, Text, JSON
from sqlalchemy.orm import relationship

from database import Base


class Organization(Base):
    """Organization entity for multi-tenant isolation."""
    
    __tablename__ = "organizations"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    api_key_hash = Column(String(64), unique=True, nullable=False)
    # Bug #34 fixed: datetime.utcnow is deprecated since Python 3.12.
    # Use timezone-aware datetime.now(timezone.utc) instead.
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    plan = Column(Enum("free", "pro", "enterprise", name="plan_types"), default="free", nullable=False)
    description = Column(Text, nullable=True)
    contact_email = Column(String(255), nullable=True)
    website = Column(String(255), nullable=True)
    
    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    llm_configs = relationship("LLMConfig", back_populates="organization", cascade="all, delete-orphan")
    # Bug #28 fixed: new OrgSettings model for persisting integration config
    settings = relationship("OrgSettings", back_populates="organization", uselist=False, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Organization(id='{self.id}', name='{self.name}', plan='{self.plan}')>"


class OrgSettings(Base):
    """Organization-level settings (CI/CD integrations, notifications, etc.)."""

    __tablename__ = "org_settings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), nullable=False, index=True)
    # Store integration config as JSON — allows extensible key/value pairs.
    integration_config = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    organization = relationship("Organization", back_populates="settings")

    def __repr__(self):
        return f"<OrgSettings(id='{self.id}', org_id='{self.org_id}')>"
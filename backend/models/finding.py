# ============================================
# SentinelAI - Finding & LLMConfig Models
# ============================================
"""
Finding model for individual security findings.
LLMConfig model for organization-specific LLM settings.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, JSON, Text, Boolean, Integer, Float
from sqlalchemy.orm import relationship

from database import Base


class Finding(Base):
    """Individual security finding/vulnerability."""
    
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    
    # Classification
    module = Column(String(50), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum("critical", "high", "medium", "low", "info", name="severity_levels"), nullable=False, index=True)
    
    # Standard identifiers
    cwe_id = Column(String(20), nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    
    # Location
    url = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    parameter = Column(String(255), nullable=True)
    method = Column(String(20), nullable=True)
    
    # Evidence
    evidence = Column(JSON, default=dict, nullable=False)
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)
    code_snippet = Column(Text, nullable=True)
    screenshot = Column(String(500), nullable=True)
    
    # Remediation (often LLM-generated)
    remediation = Column(Text, nullable=True)
    remediation_steps = Column(JSON, default=list, nullable=False)
    code_fix_before = Column(Text, nullable=True)
    code_fix_after = Column(Text, nullable=True)
    references = Column(JSON, default=list, nullable=False)
    
    # Management
    false_positive = Column(Boolean, default=False, nullable=False)
    status = Column(Enum("open", "fixed", "accepted_risk", "false_positive", name="finding_status"), default="open", nullable=False)
    
    # AI analysis
    ai_explanation = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    
    # Metadata
    tool_source = Column(String(50), nullable=True)
    tags = Column(JSON, default=list, nullable=False)
    
    # Timestamps
    # Bug #34 fixed: datetime.utcnow deprecated since Python 3.12.
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    
    def to_dict(self):
        """Serialize finding to dictionary."""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "module": self.module,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "url": self.url,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "parameter": self.parameter,
            "method": self.method,
            "evidence": self.evidence,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "remediation_steps": self.remediation_steps,
            "code_fix": {
                "before": self.code_fix_before,
                "after": self.code_fix_after,
            } if self.code_fix_before or self.code_fix_after else None,
            "references": self.references,
            "false_positive": self.false_positive,
            "status": self.status,
            "ai_explanation": self.ai_explanation,
            "ai_confidence": self.ai_confidence,
            "tool_source": self.tool_source,
            "tags": self.tags,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
    
    def __repr__(self):
        return f"<Finding(id='{self.id}', title='{self.title[:50]}...', severity='{self.severity}')>"


class LLMConfig(Base):
    """Organization-specific LLM configuration."""
    
    __tablename__ = "llm_configs"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Provider settings
    provider = Column(Enum("deepseek", "openai", "anthropic", "groq", "ollama", name="llm_providers"), nullable=False)
    model = Column(String(100), nullable=False)
    api_key_encrypted = Column(Text, nullable=True)
    base_url = Column(String(500), nullable=True)
    
    # Model parameters
    temperature = Column(Float, default=0.1, nullable=True)
    max_tokens = Column(Integer, default=4096, nullable=True)
    
    # Feature toggles
    enable_code_review = Column(Boolean, default=True, nullable=False)
    enable_correlation = Column(Boolean, default=True, nullable=False)
    enable_remediation = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    
    # Relationships
    organization = relationship("Organization", back_populates="llm_configs")
    
    def __repr__(self):
        return f"<LLMConfig(id='{self.id}', provider='{self.provider}', model='{self.model}')>"
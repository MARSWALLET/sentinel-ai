# ============================================
# SentinelAI - Scan Model
# ============================================
"""
Scan model to track security scan jobs.
Links to organization, user, findings, and reports.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Enum, ForeignKey, JSON, Integer, Float, Text
from sqlalchemy.orm import relationship

from database import Base


class Scan(Base):
    """Scan entity representing a security scan job."""
    
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org_id = Column(String(36), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    
    # Input details
    input_type = Column(Enum("url", "github", "upload", "paste", "api_endpoint", name="input_types"), nullable=False)
    input_value = Column(Text, nullable=False)
    input_metadata = Column(JSON, default=dict, nullable=False)
    
    # Scan configuration
    modules_run = Column(JSON, default=list, nullable=False)
    scan_config = Column(JSON, default=dict, nullable=False)
    
    # Status tracking
    status = Column(
        Enum("pending", "queued", "running", "completing", "complete", "failed", "cancelled", name="scan_status"),
        default="pending",
        nullable=False,
    )
    
    # Timing
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Results summary
    risk_score = Column(Integer, nullable=True)
    grade = Column(String(1), nullable=True)
    executive_summary = Column(Text, nullable=True)
    compliance_notes = Column(JSON, nullable=True)
    attack_chains = Column(JSON, default=list, nullable=False)
    
    # Statistics
    stats_critical = Column(Integer, default=0, nullable=False)
    stats_high = Column(Integer, default=0, nullable=False)
    stats_medium = Column(Integer, default=0, nullable=False)
    stats_low = Column(Integer, default=0, nullable=False)
    stats_info = Column(Integer, default=0, nullable=False)
    stats_total = Column(Integer, default=0, nullable=False)
    
    # Module results tracking
    module_results = Column(JSON, default=dict, nullable=False)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    failed_modules = Column(JSON, default=list, nullable=False)
    
    # Bug #34 fixed: datetime.utcnow is deprecated in Python 3.12+.
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    
    # Relationships
    organization = relationship("Organization", back_populates="scans")
    user = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    
    def calculate_risk_score(self):
        """Calculate overall risk score based on findings."""
        # Bug #29 fixed: stats_* can be None if a partial DB write occurred.
        # Coerce to int to prevent TypeError in arithmetic.
        critical = int(self.stats_critical or 0)
        high = int(self.stats_high or 0)
        medium = int(self.stats_medium or 0)
        low = int(self.stats_low or 0)
        info = int(self.stats_info or 0)
        total = critical + high + medium + low + info
        if total == 0:
            self.risk_score = 0
            return 0
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}
        score = (
            critical * weights["critical"] +
            high * weights["high"] +
            medium * weights["medium"] +
            low * weights["low"] +
            info * weights["info"]
        )
        self.risk_score = min(int(score), 100)
        return self.risk_score
    
    def calculate_grade(self):
        """Calculate letter grade from risk score."""
        if self.risk_score is None:
            self.calculate_risk_score()
        
        score = self.risk_score or 0
        if score >= 80:
            self.grade = "F"
        elif score >= 60:
            self.grade = "D"
        elif score >= 40:
            self.grade = "C"
        elif score >= 20:
            self.grade = "B"
        else:
            self.grade = "A"
        return self.grade
    
    def update_stats(self):
        """Recalculate statistics from findings."""
        self.stats_total = (
            (self.stats_critical or 0) + (self.stats_high or 0) +
            (self.stats_medium or 0) + (self.stats_low or 0) + (self.stats_info or 0)
        )
    
    def to_summary_dict(self):
        """Serialize scan summary."""
        return {
            "id": self.id,
            "input_type": self.input_type,
            "input_value": self.input_value,
            "status": self.status,
            "modules_run": self.modules_run,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "statistics": {
                "critical": self.stats_critical,
                "high": self.stats_high,
                "medium": self.stats_medium,
                "low": self.stats_low,
                "info": self.stats_info,
                "total": self.stats_total,
            },
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
    
    def __repr__(self):
        return f"<Scan(id='{self.id}', type='{self.input_type}', status='{self.status}')>"


class Report(Base):
    """Report entity for generated scan reports."""
    
    __tablename__ = "reports"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    format = Column(Enum("json", "html", "pdf", name="report_formats"), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=True)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")
    
    def __repr__(self):
        return f"<Report(id='{self.id}', scan_id='{self.scan_id}', format='{self.format}')>"
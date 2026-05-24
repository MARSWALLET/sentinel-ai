# ============================================
# SentinelAI - Findings Router
# ============================================
"""
Finding management endpoints:
- GET /api/scans/{scan_id}/findings — list all findings
- GET /api/scans/{scan_id}/findings?severity=critical — filter findings
- PATCH /api/findings/{finding_id} — update status/false_positive
- GET /api/findings/stats — organization-wide statistics
"""

import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func, desc, and_, case
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.finding import Finding
from models.scan import Scan
from models.user import User
from routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()


# --- Pydantic Schemas ---

class FindingUpdateRequest(BaseModel):
    status: Optional[str] = Field(default=None, pattern=r"^(open|fixed|accepted_risk|false_positive)$")
    false_positive: Optional[bool] = None
    notes: Optional[str] = None


class FindingsListResponse(BaseModel):
    findings: List[dict]
    total: int
    page: int
    page_size: int


class SeverityStats(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ModuleStats(BaseModel):
    module: str
    count: int


class FindingsStatsResponse(BaseModel):
    by_severity: SeverityStats
    by_module: List[ModuleStats]
    by_status: dict
    total_findings: int
    recent_findings: List[dict]


# --- Endpoints ---

@router.get("/scans/{scan_id}/findings", response_model=FindingsListResponse)
async def list_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, pattern=r"^(critical|high|medium|low|info)$"),
    module: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status", pattern=r"^(open|fixed|accepted_risk|false_positive)$"),
    false_positive: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List all findings for a scan with optional filtering.
    Supports filtering by severity, module, status, and false positive flag.
    """
    # Verify scan belongs to user's org
    result = await db.execute(
        select(Scan).where(and_(Scan.id == scan_id, Scan.org_id == current_user.org_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Build query
    query = select(Finding).where(Finding.scan_id == scan_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    if module:
        query = query.where(Finding.module == module)
    if status_filter:
        query = query.where(Finding.status == status_filter)
    if false_positive is not None:
        query = query.where(Finding.false_positive == false_positive)
    
    # Count total
    count_query = select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
    if severity:
        count_query = count_query.where(Finding.severity == severity)
    if module:
        count_query = count_query.where(Finding.module == module)
    if status_filter:
        count_query = count_query.where(Finding.status == status_filter)
    if false_positive is not None:
        count_query = count_query.where(Finding.false_positive == false_positive)
    
    result = await db.execute(count_query)
    total = result.scalar() or 0
    
    # Get paginated results
    query = query.order_by(
        case(
            (Finding.severity == "critical", 1),
            (Finding.severity == "high", 2),
            (Finding.severity == "medium", 3),
            (Finding.severity == "low", 4),
            (Finding.severity == "info", 5),
            else_=6,
        ),
        desc(Finding.cvss_score),
    ).offset((page - 1) * page_size).limit(page_size)
    
    result = await db.execute(query)
    findings = result.scalars().all()
    
    return FindingsListResponse(
        findings=[f.to_dict() for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.patch("/findings/{finding_id}")
async def update_finding(
    finding_id: str,
    request: FindingUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Update a finding's status or false positive flag.
    """
    # Get finding with org verification
    result = await db.execute(
        select(Finding, Scan).join(Scan).where(
            and_(Finding.id == finding_id, Scan.org_id == current_user.org_id)
        )
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding = row[0]
    
    # Update fields
    if request.status:
        finding.status = request.status
    if request.false_positive is not None:
        finding.false_positive = request.false_positive
        if request.false_positive:
            finding.status = "false_positive"
    if request.notes:
        # Append to evidence
        notes = finding.evidence.get("notes", [])
        notes.append({
            "user_id": current_user.id,
            "note": request.notes,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        finding.evidence["notes"] = notes
    
    await db.commit()
    logger.info(f"Finding {finding_id} updated by {current_user.email}")
    
    return finding.to_dict()


@router.get("/findings/stats", response_model=FindingsStatsResponse)
async def get_findings_stats(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get organization-wide finding statistics.
    """
    from datetime import datetime, timedelta
    
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Get scans in time period
    result = await db.execute(
        select(Scan.id).where(
            and_(Scan.org_id == current_user.org_id, Scan.created_at >= cutoff)
        )
    )
    scan_ids = [r[0] for r in result.all()]
    
    if not scan_ids:
        return FindingsStatsResponse(
            by_severity=SeverityStats(critical=0, high=0, medium=0, low=0, info=0),
            by_module=[],
            by_status={},
            total_findings=0,
            recent_findings=[],
        )
    
    # Severity counts
    result = await db.execute(
        select(Finding.severity, func.count(Finding.id)).where(
            Finding.scan_id.in_(scan_ids)
        ).group_by(Finding.severity)
    )
    severity_counts = {row[0]: row[1] for row in result.all()}
    
    # Module counts
    result = await db.execute(
        select(Finding.module, func.count(Finding.id)).where(
            Finding.scan_id.in_(scan_ids)
        ).group_by(Finding.module).order_by(desc(func.count(Finding.id)))
    )
    module_counts = [ModuleStats(module=row[0], count=row[1]) for row in result.all()]
    
    # Status counts
    result = await db.execute(
        select(Finding.status, func.count(Finding.id)).where(
            Finding.scan_id.in_(scan_ids)
        ).group_by(Finding.status)
    )
    status_counts = {row[0]: row[1] for row in result.all()}
    
    # Total
    result = await db.execute(
        select(func.count(Finding.id)).where(Finding.scan_id.in_(scan_ids))
    )
    total = result.scalar() or 0
    
    # Recent critical/high findings
    result = await db.execute(
        select(Finding).where(
            and_(
                Finding.scan_id.in_(scan_ids),
                Finding.severity.in_(["critical", "high"]),
                Finding.status == "open",
            )
        ).order_by(desc(Finding.created_at)).limit(10)
    )
    recent = [f.to_dict() for f in result.scalars().all()]
    
    return FindingsStatsResponse(
        by_severity=SeverityStats(
            critical=severity_counts.get("critical", 0),
            high=severity_counts.get("high", 0),
            medium=severity_counts.get("medium", 0),
            low=severity_counts.get("low", 0),
            info=severity_counts.get("info", 0),
        ),
        by_module=module_counts,
        by_status=status_counts,
        total_findings=total,
        recent_findings=recent,
    )

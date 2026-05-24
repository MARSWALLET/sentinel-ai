# ============================================
# SentinelAI - Reports Router
# ============================================
"""
Report generation and download endpoints:
- GET /api/scans/{scan_id}/report/json — download JSON report
- GET /api/scans/{scan_id}/report/html — download HTML report
- GET /api/scans/{scan_id}/report/pdf — download PDF report
"""

import logging
import os
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.scan import Scan, Report as ReportModel
from models.finding import Finding
from models.user import User
from routers.auth import get_current_user
from services.report_service import ReportService

logger = logging.getLogger(__name__)
router = APIRouter()


# --- Endpoints ---

@router.get("/scans/{scan_id}/report/json")
async def get_json_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Download JSON report for a scan.
    Returns the complete scan data with all findings in structured JSON format.
    """
    # Verify scan belongs to user's org
    result = await db.execute(
        select(Scan).where(and_(Scan.id == scan_id, Scan.org_id == current_user.org_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get all findings
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()
    
    # Build JSON report
    report_data = {
        "scan_id": scan.id,
        "target": scan.input_value,
        "scan_type": scan.input_type,
        "scan_date": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "risk_score": scan.risk_score,
        "grade": scan.grade,
        "executive_summary": scan.executive_summary,
        "compliance_notes": scan.compliance_notes or {},
        "statistics": {
            "critical": scan.stats_critical,
            "high": scan.stats_high,
            "medium": scan.stats_medium,
            "low": scan.stats_low,
            "info": scan.stats_info,
            "total": scan.stats_total,
        },
        "attack_chains": scan.attack_chains or [],
        "findings": [f.to_dict() for f in findings],
        "assets_discovered": scan.input_metadata.get("assets", {}),
        "modules_run": scan.modules_run,
        "failed_modules": scan.failed_modules,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
    
    # Save report to file
    report_dir = f"{settings.REPORTS_DIR}/{scan_id}"
    os.makedirs(report_dir, exist_ok=True)
    report_path = f"{report_dir}/report.json"
    
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    
    # Record report
    result = await db.execute(
        select(ReportModel).where(
            and_(ReportModel.scan_id == scan_id, ReportModel.format == "json")
        )
    )
    existing = result.scalar_one_or_none()
    
    if not existing:
        report_record = ReportModel(
            scan_id=scan_id,
            format="json",
            file_path=report_path,
            file_size=os.path.getsize(report_path),
        )
        db.add(report_record)
        await db.commit()
    
    return FileResponse(
        report_path,
        media_type="application/json",
        filename=f"sentinelai-report-{scan_id}.json",
    )


@router.get("/scans/{scan_id}/report/html")
async def get_html_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Download HTML report for a scan.
    Professional branded layout with color-coded severity badges, collapsible sections, and charts.
    """
    # Verify scan belongs to user's org
    result = await db.execute(
        select(Scan).where(and_(Scan.id == scan_id, Scan.org_id == current_user.org_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check if HTML report already exists
    result = await db.execute(
        select(ReportModel).where(
            and_(ReportModel.scan_id == scan_id, ReportModel.format == "html")
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing and os.path.exists(existing.file_path):
        return FileResponse(
            existing.file_path,
            media_type="text/html",
            filename=f"sentinelai-report-{scan_id}.html",
        )
    
    # Generate HTML report
    report_service = ReportService()
    
    # Get all findings
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()
    
    # Generate report
    report_data = {
        "scan": scan,
        "findings": findings,
    }
    
    try:
        report_path = await report_service.generate_html_report(scan_id, report_data)
    except Exception as e:
        logger.error(f"Failed to generate HTML report for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate HTML report: {str(e)}")
    
    # Record report
    if existing:
        existing.file_path = report_path
        existing.file_size = os.path.getsize(report_path)
    else:
        report_record = ReportModel(
            scan_id=scan_id,
            format="html",
            file_path=report_path,
            file_size=os.path.getsize(report_path),
        )
        db.add(report_record)
    
    await db.commit()
    
    return FileResponse(
        report_path,
        media_type="text/html",
        filename=f"sentinelai-report-{scan_id}.html",
    )


@router.get("/scans/{scan_id}/report/pdf")
async def get_pdf_report(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Download PDF report for a scan.
    Generated from HTML using WeasyPrint for professional output.
    """
    # Verify scan belongs to user's org
    result = await db.execute(
        select(Scan).where(and_(Scan.id == scan_id, Scan.org_id == current_user.org_id))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Check if PDF already exists
    result = await db.execute(
        select(ReportModel).where(
            and_(ReportModel.scan_id == scan_id, ReportModel.format == "pdf")
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing and os.path.exists(existing.file_path):
        return FileResponse(
            existing.file_path,
            media_type="application/pdf",
            filename=f"sentinelai-report-{scan_id}.pdf",
        )
    
    # Generate PDF via HTML
    report_service = ReportService()
    
    # Get all findings
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()
    
    report_data = {
        "scan": scan,
        "findings": findings,
    }
    
    try:
        report_path = await report_service.generate_pdf_report(scan_id, report_data)
    except Exception as e:
        logger.error(f"Failed to generate PDF report for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")
    
    # Record report
    if existing:
        existing.file_path = report_path
        existing.file_size = os.path.getsize(report_path)
    else:
        report_record = ReportModel(
            scan_id=scan_id,
            format="pdf",
            file_path=report_path,
            file_size=os.path.getsize(report_path),
        )
        db.add(report_record)
    
    await db.commit()
    
    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"sentinelai-report-{scan_id}.pdf",
    )
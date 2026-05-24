# ============================================
# SentinelAI - Scans Router
# ============================================
"""
Scan management endpoints:
- POST /api/scans/url — start URL scan
- POST /api/scans/github — start GitHub repo scan
- POST /api/scans/upload — start uploaded code scan
- POST /api/scans/paste — start raw code paste scan
- GET /api/scans — list all scans for org
- GET /api/scans/{id} — get scan details + status
- DELETE /api/scans/{id} — delete scan
"""

import logging
import shutil
import uuid
import asyncio
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select, desc, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.scan import Scan
from models.finding import Finding
from models.user import User
from routers.auth import get_current_user
from tasks.scan_tasks import (
    run_url_scan,
    run_github_scan,
    run_upload_scan,
    run_paste_scan,
    run_api_endpoint_scan,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# --- Pydantic Schemas ---

class URLScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, description="Target URL to scan")
    modules: Optional[List[str]] = Field(default=None, description="Modules to run (default: all)")
    scan_depth: str = Field(default="standard", pattern=r"^(quick|standard|deep)$")
    max_pages: int = Field(default=100, ge=1, le=10000)
    auth_cookie: Optional[str] = None
    auth_header: Optional[str] = None
    custom_headers: Optional[dict] = None


class GitHubScanRequest(BaseModel):
    repo_url: str = Field(..., min_length=1, description="GitHub repository URL")
    branch: str = Field(default="main")
    github_token: Optional[str] = None
    modules: Optional[List[str]] = Field(default=None)
    scan_depth: str = Field(default="standard", pattern=r"^(quick|standard|deep)$")


class PasteScanRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Raw code to scan")
    language: Optional[str] = Field(default=None, description="Programming language (auto-detected if not provided)")
    filename: str = Field(default="pasted_code")
    modules: Optional[List[str]] = Field(default=None)


class APIEndpointScanRequest(BaseModel):
    base_url: str = Field(..., description="API base URL")
    spec_url: Optional[str] = Field(default=None, description="OpenAPI/Swagger spec URL")
    spec_content: Optional[str] = Field(default=None, description="OpenAPI spec content (JSON/YAML)")
    auth_token: Optional[str] = None
    custom_headers: Optional[dict] = None
    modules: Optional[List[str]] = Field(default=None)


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    input_type: str
    input_value: str


class ScanListResponse(BaseModel):
    scans: List[dict]
    total: int
    page: int
    page_size: int


# --- Helper Functions ---

def validate_target(target: str, input_type: str) -> None:
    """Validate scan target for security."""
    from urllib.parse import urlparse
    
    # Parse URL
    parsed = urlparse(target if target.startswith("http") else f"http://{target}")
    
    # Block localhost/private IPs in non-self-hosted mode
    if not settings.SELF_HOSTED_MODE:
        hostname = parsed.hostname or ""
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            raise HTTPException(status_code=400, detail="Scanning localhost is not allowed")
        
        # Check for private IP ranges
        import ipaddress
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast:
                raise HTTPException(status_code=400, detail="Scanning internal IP addresses is not allowed")
        except ValueError:
            pass  # Not an IP, probably a domain


async def save_upload_file(upload_file: UploadFile, scan_id: str) -> str:
    """Save uploaded file to workspace asynchronously."""
    # Bug #4 fixed: previously used synchronous shutil.copyfileobj inside an
    # async route, which blocked the entire event loop.
    import os
    import aiofiles
    workspace = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}"
    os.makedirs(workspace, exist_ok=True)
    
    file_path = f"{workspace}/{upload_file.filename or 'upload.zip'}"
    async with aiofiles.open(file_path, "wb") as out_file:
        while chunk := await upload_file.read(65536):  # 64 KB chunks
            await out_file.write(chunk)
    
    return file_path


# --- Endpoints ---

@router.post("/url", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_url_scan(
    request: URLScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Start a URL security scan.
    Orchestrates reconnaissance, web application, SSL/TLS, and network scanning modules.
    """
    validate_target(request.target_url, "url")
    
    # Create scan record
    scan = Scan(
        org_id=current_user.org_id,
        user_id=current_user.id,
        input_type="url",
        input_value=request.target_url,
        input_metadata={
            "scan_depth": request.scan_depth,
            "max_pages": request.max_pages,
            "auth_cookie": bool(request.auth_cookie),
            "auth_header": bool(request.auth_header),
        },
        scan_config=request.model_dump(),
        modules_run=request.modules or ["recon", "web", "ssl", "network"],
        status="queued",
    )
    db.add(scan)
    await db.commit()
    
    # Queue Celery task
    task = run_url_scan.delay(scan.id, request.model_dump())
    logger.info(f"URL scan queued: scan_id={scan.id}, task_id={task.id}, target={request.target_url}")
    
    return ScanResponse(
        scan_id=scan.id,
        status="queued",
        message=f"URL scan queued for {request.target_url}. Use GET /api/scans/{scan.id} for status.",
        input_type="url",
        input_value=request.target_url,
    )


@router.post("/github", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_github_scan(
    request: GitHubScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Start a GitHub repository security scan.
    Clones repo, runs SAST, secrets scanning, dependency scanning, and IaC scanning.
    """
    # Bug #12 fixed: SSRF validation was missing for GitHub scans. An attacker
    # could supply an internal GitHub Enterprise URL or internal IP disguised as
    # a GitHub URL to trigger scans against internal infrastructure.
    validate_target(request.repo_url, "github")
    
    scan = Scan(
        org_id=current_user.org_id,
        user_id=current_user.id,
        input_type="github",
        input_value=request.repo_url,
        input_metadata={
            "branch": request.branch,
            "has_token": bool(request.github_token),
        },
        scan_config=request.model_dump(),
        modules_run=request.modules or ["sast", "secrets", "dependencies", "infrastructure", "ai_review"],
        status="queued",
    )
    db.add(scan)
    await db.commit()
    
    task = run_github_scan.delay(scan.id, request.model_dump())
    logger.info(f"GitHub scan queued: scan_id={scan.id}, repo={request.repo_url}")
    
    return ScanResponse(
        scan_id=scan.id,
        status="queued",
        message=f"GitHub scan queued for {request.repo_url}. Use GET /api/scans/{scan.id} for status.",
        input_type="github",
        input_value=request.repo_url,
    )


@router.post("/upload", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_upload_scan(
    file: UploadFile = File(..., description="ZIP file or folder to scan"),
    modules: Optional[str] = Form(default=None),
    scan_depth: str = Form(default="standard"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Start a code upload scan.
    Accepts ZIP files, extracts and runs SAST, secrets, dependency, and IaC scanning.
    """
    # Validate file type
    if not file.filename or not (file.filename.endswith(".zip") or file.filename.endswith(".tar.gz")):
        raise HTTPException(status_code=400, detail="Only .zip and .tar.gz files are supported")
    
    # Bug #5 fixed: enforce file size limit BEFORE writing to disk.
    # Previously MAX_FILE_SIZE_MB was configured but never checked.
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if file.size and file.size > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {settings.MAX_FILE_SIZE_MB} MB.",
        )
    
    scan_id = str(uuid.uuid4())
    # Bug #4 fixed: save_upload_file is now async.
    file_path = await save_upload_file(file, scan_id)
    
    # Verify size after write (catches cases where Content-Length was absent)
    import os
    actual_size = os.path.getsize(file_path)
    if actual_size > max_bytes:
        os.remove(file_path)
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {settings.MAX_FILE_SIZE_MB} MB.",
        )
    
    module_list = modules.split(",") if modules else ["sast", "secrets", "dependencies", "infrastructure", "ai_review"]
    
    scan = Scan(
        id=scan_id,
        org_id=current_user.org_id,
        user_id=current_user.id,
        input_type="upload",
        input_value=file.filename or "uploaded_code",
        input_metadata={
            "original_filename": file.filename,
            "file_path": file_path,
            "scan_depth": scan_depth,
        },
        scan_config={"file_path": file_path, "modules": module_list, "scan_depth": scan_depth},
        modules_run=module_list,
        status="queued",
    )
    db.add(scan)
    await db.commit()
    
    task = run_upload_scan.delay(scan_id, {"file_path": file_path, "modules": module_list, "scan_depth": scan_depth})
    logger.info(f"Upload scan queued: scan_id={scan_id}, file={file.filename}")
    
    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Upload scan queued for {file.filename}. Use GET /api/scans/{scan_id} for status.",
        input_type="upload",
        input_value=file.filename or "uploaded_code",
    )


@router.post("/paste", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_paste_scan(
    request: PasteScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Start a raw code paste scan.
    Detects language, runs appropriate SAST tools, and performs AI code review.
    """
    scan_id = str(uuid.uuid4())
    
    # Save code to file
    workspace = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}"
    import os
    os.makedirs(workspace, exist_ok=True)
    file_path = f"{workspace}/{request.filename}"
    with open(file_path, "w") as f:
        f.write(request.code)
    
    module_list = request.modules or ["sast", "ai_review"]
    
    scan = Scan(
        id=scan_id,
        org_id=current_user.org_id,
        user_id=current_user.id,
        input_type="paste",
        input_value=request.filename,
        input_metadata={
            "language": request.language,
            "code_length": len(request.code),
            "file_path": file_path,
        },
        scan_config={
            "file_path": file_path,
            # Bug #13 fixed: raw code is NOT stored in the DB scan_config.
            # It is already written to disk at file_path. Storing it again in
            # the DB column wastes space and unnecessarily exposes user code.
            "language": request.language,
            "modules": module_list,
        },
        modules_run=module_list,
        status="queued",
    )
    db.add(scan)
    await db.commit()
    
    task = run_paste_scan.delay(scan_id, {
        "file_path": file_path,
        "code": request.code,
        "language": request.language,
        "modules": module_list,
    })
    logger.info(f"Paste scan queued: scan_id={scan_id}")
    
    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Code paste scan queued. Use GET /api/scans/{scan_id} for status.",
        input_type="paste",
        input_value=request.filename,
    )


@router.post("/api_endpoint", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_api_endpoint_scan(
    request: APIEndpointScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Start an API endpoint security scan.
    Tests for OWASP API Top 10 vulnerabilities, authentication issues, and injection flaws.
    """
    validate_target(request.base_url, "api_endpoint")
    
    scan = Scan(
        org_id=current_user.org_id,
        user_id=current_user.id,
        input_type="api_endpoint",
        input_value=request.base_url,
        input_metadata={
            "has_spec": bool(request.spec_url or request.spec_content),
            "auth_provided": bool(request.auth_token),
        },
        scan_config=request.model_dump(),
        modules_run=request.modules or ["api_security"],
        status="queued",
    )
    db.add(scan)
    await db.commit()
    
    task = run_api_endpoint_scan.delay(scan.id, request.model_dump())
    logger.info(f"API endpoint scan queued: scan_id={scan.id}, target={request.base_url}")
    
    return ScanResponse(
        scan_id=scan.id,
        status="queued",
        message=f"API endpoint scan queued for {request.base_url}. Use GET /api/scans/{scan.id} for status.",
        input_type="api_endpoint",
        input_value=request.base_url,
    )


@router.get("", response_model=ScanListResponse)
async def list_scans(
    status: Optional[str] = Query(None, pattern=r"^(pending|queued|running|completing|complete|failed|cancelled)$"),
    input_type: Optional[str] = Query(None, pattern=r"^(url|github|upload|paste|api_endpoint)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List all scans for the current user's organization.
    Supports filtering by status and input type.
    """
    # Build query
    query = select(Scan).where(Scan.org_id == current_user.org_id)
    
    if status:
        query = query.where(Scan.status == status)
    if input_type:
        query = query.where(Scan.input_type == input_type)
    
    # Bug #10 fixed: previously fetched ALL matching rows just to count them.
    # Use SQL COUNT to avoid loading thousands of Scan objects into memory.
    count_query = select(func.count(Scan.id)).where(Scan.org_id == current_user.org_id)
    if status:
        count_query = count_query.where(Scan.status == status)
    if input_type:
        count_query = count_query.where(Scan.input_type == input_type)
    
    total = (await db.execute(count_query)).scalar_one()
    
    # Get paginated results
    query = query.order_by(desc(Scan.created_at)).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    scans = result.scalars().all()
    
    return ScanListResponse(
        scans=[s.to_summary_dict() for s in scans],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed scan information including status, statistics, and module results.
    """
    result = await db.execute(
        select(Scan).where(and_(Scan.id == scan_id, Scan.org_id == current_user.org_id))
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get findings count by severity
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = result.scalars().all()
    
    response = scan.to_summary_dict()
    response["findings_preview"] = [f.to_dict() for f in findings[:20]]  # First 20 findings
    response["findings_count"] = len(findings)
    response["failed_modules"] = scan.failed_modules
    response["error_message"] = scan.error_message
    
    return response


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a scan and all associated data.
    """
    result = await db.execute(
        select(Scan).where(and_(Scan.id == scan_id, Scan.org_id == current_user.org_id))
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Clean up workspace files
    workspace = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}"
    try:
        shutil.rmtree(workspace, ignore_errors=True)
    except Exception as e:
        logger.warning(f"Failed to clean up workspace for scan {scan_id}: {e}")
    
    await db.delete(scan)
    await db.commit()
    
    logger.info(f"Scan deleted: {scan_id}")
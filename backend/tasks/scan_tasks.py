# ============================================
# SentinelAI - Scan Tasks
# ============================================
"""
Celery tasks for running security scans.
Each task runs the full scan pipeline and updates the database.
"""

import asyncio
import logging
import shutil
import time
from datetime import datetime
from typing import Any, Dict, List

from celery import shared_task, Task
from celery.exceptions import MaxRetriesExceededError, SoftTimeLimitExceeded

from config import settings
from tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


class ScanTask(Task):
    """Base scan task with common functionality."""
    
    # Bug #7 fixed: autoretry_for=(Exception,) was too broad — it retried on
    # every error including deliberate scan failures, SoftTimeLimitExceeded,
    # and DB integrity errors. Narrowed to transient infrastructure errors only.
    autoretry_for = (ConnectionError, TimeoutError, OSError)
    retry_backoff = True
    retry_backoff_max = 300
    retry_kwargs = {"max_retries": 2}
    soft_time_limit = settings.CELERY_TASK_TIME_LIMIT
    time_limit = settings.CELERY_TASK_TIME_LIMIT + 60
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure."""
        scan_id = args[0] if args else "unknown"
        logger.error(f"Scan task failed: scan_id={scan_id}, error={exc}")
        
        # Update scan status
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._update_scan_status(scan_id, "failed", str(exc)))
            loop.close()
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")
    
    async def _update_scan_status(self, scan_id: str, status: str, error: str = None):
        """Update scan status in database."""
        try:
            from database import async_session_maker
            from models.scan import Scan
            from sqlalchemy import select
            
            async with async_session_maker() as session:
                result = await session.execute(select(Scan).where(Scan.id == scan_id))
                scan = result.scalar_one_or_none()
                if scan:
                    scan.status = status
                    if error:
                        scan.error_message = error
                    if status in ("complete", "failed"):
                        scan.completed_at = datetime.now(timezone.utc)
                        if scan.started_at:
                            scan.duration_seconds = int((datetime.now(timezone.utc) - scan.started_at).total_seconds())
                    await session.commit()
        except Exception as e:
            logger.error(f"Database update failed: {e}")


async def _run_scan_pipeline(scan_id: str, input_type: str, target: str,
                              modules: List[str], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the scan pipeline and update the database.
    
    Args:
        scan_id: Scan ID
        input_type: Type of input
        target: Scan target
        modules: Modules to run
        config: Scan configuration
        
    Returns:
        Scan results dict
    """
    from database import async_session_maker
    from models.scan import Scan
    # Bug #6 fixed: Finding lives in models.finding, NOT models.scan.
    # The original import raised ImportError at runtime, crashing every scan task.
    from models.finding import Finding
    from scanner.orchestrator import ScanOrchestrator
    from services.llm_service import LLMService
    from sqlalchemy import select
    
    start_time = time.time()
    
    # Update scan to running
    async with async_session_maker() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error(f"Scan not found: {scan_id}")
            return {"error": "Scan not found"}
        
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await session.commit()
    
    try:
        # Run scan orchestrator
        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            target=target,
            input_type=input_type,
            modules=modules,
            config=config,
        )
        
        results = await orchestrator.run()
        
        # Get findings from results
        all_findings = results.get("findings", [])
        
        # Store findings in database
        async with async_session_maker() as session:
            for finding_data in all_findings:
                finding = Finding(
                    scan_id=scan_id,
                    module=finding_data.get("module", "unknown"),
                    title=finding_data.get("title", "Unknown")[:500],
                    description=finding_data.get("description", ""),
                    severity=finding_data.get("severity", "info"),
                    cwe_id=finding_data.get("cwe_id"),
                    cvss_score=finding_data.get("cvss_score"),
                    url=finding_data.get("url"),
                    file_path=finding_data.get("file_path"),
                    line_number=finding_data.get("line_number"),
                    parameter=finding_data.get("parameter"),
                    evidence=finding_data.get("evidence", {}),
                    code_snippet=finding_data.get("code_snippet"),
                    remediation=finding_data.get("remediation"),
                    tool_source=finding_data.get("tool_source"),
                    ai_explanation=finding_data.get("ai_explanation"),
                    ai_confidence=finding_data.get("ai_confidence"),
                    references=finding_data.get("references", []),
                )
                session.add(finding)
            
            # Update scan with results
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one()
            
            # Count by severity
            severity_counts = {}
            for finding_data in all_findings:
                sev = finding_data.get("severity", "info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            scan.stats_critical = severity_counts.get("critical", 0)
            scan.stats_high = severity_counts.get("high", 0)
            scan.stats_medium = severity_counts.get("medium", 0)
            scan.stats_low = severity_counts.get("low", 0)
            scan.stats_info = severity_counts.get("info", 0)
            scan.stats_total = len(all_findings)
            
            # Calculate risk score and grade
            scan.calculate_risk_score()
            scan.calculate_grade()
            
            # Update module results
            scan.module_results = results.get("module_results", {})
            scan.failed_modules = results.get("failed_modules", [])
            
            # Run LLM correlation if findings exist
            if all_findings and config.get("enable_llm_correlation", True):
                try:
                    llm_service = LLMService()
                    correlation = await llm_service.correlate_findings(all_findings, target)
                    
                    scan.risk_score = correlation.get("risk_score", scan.risk_score)
                    scan.grade = correlation.get("grade", scan.grade)
                    scan.executive_summary = correlation.get("executive_summary", "")
                    scan.compliance_notes = correlation.get("compliance_notes", {})
                    scan.attack_chains = correlation.get("attack_chains", [])
                    
                    # Generate remediation for critical findings
                    critical_findings = [f for f in all_findings if f.get("severity") == "critical"]
                    for cf in critical_findings[:5]:
                        try:
                            remediation = await llm_service.generate_remediation(cf)
                            # Update the finding
                            finding_result = await session.execute(
                                select(Finding).where(
                                    Finding.scan_id == scan_id,
                                    Finding.title == cf.get("title", "")[:500]
                                )
                            )
                            finding_obj = finding_result.scalar_one_or_none()
                            if finding_obj:
                                finding_obj.remediation = remediation.get("summary", "") + "\n\n" + "\n".join(remediation.get("steps", []))
                                finding_obj.remediation_steps = remediation.get("steps", [])
                                finding_obj.code_fix_before = remediation.get("code_fix", {}).get("before", "")
                                finding_obj.code_fix_after = remediation.get("code_fix", {}).get("after", "")
                                finding_obj.references = remediation.get("references", [])
                        except Exception as e:
                            logger.warning(f"LLM remediation generation failed: {e}")
                    
                except Exception as e:
                    logger.warning(f"LLM correlation failed: {e}")
            
            # Bug #25 fixed: set status to 'completing' BEFORE the commit so
            # the DB reflects intent. After a successful commit, promote to
            # 'complete'. If commit fails the status stays 'completing' and the
            # outer except block will flip it to 'failed'.
            scan.status = "completing"
            scan.completed_at = datetime.now(timezone.utc)
            scan.duration_seconds = int(time.time() - start_time)
            
            await session.commit()
            
            # Promote to 'complete' only after confirmed commit
            async with async_session_maker() as confirm_session:
                result2 = await confirm_session.execute(select(Scan).where(Scan.id == scan_id))
                scan2 = result2.scalar_one_or_none()
                if scan2 and scan2.status == "completing":
                    scan2.status = "complete"
                    await confirm_session.commit()
        
        logger.info(f"Scan {scan_id} complete: {len(all_findings)} findings, grade={scan.grade}, risk={scan.risk_score}")
        
        # Clean up workspace (keep for now, can be cleaned later)
        # _cleanup_workspace(scan_id)
        
        return results
        
    except SoftTimeLimitExceeded:
        logger.error(f"Scan {scan_id} exceeded time limit")
        async with async_session_maker() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = "failed"
                scan.error_message = f"Scan exceeded time limit of {settings.CELERY_TASK_TIME_LIMIT} seconds"
                scan.completed_at = datetime.now(timezone.utc)
                await session.commit()
        raise
        
    except Exception as e:
        logger.exception(f"Scan {scan_id} failed: {e}")
        async with async_session_maker() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.now(timezone.utc)
                if scan.started_at:
                    scan.duration_seconds = int((datetime.now(timezone.utc) - scan.started_at).total_seconds())
                await session.commit()
        raise


def _cleanup_workspace(scan_id: str):
    """Clean up scan workspace files."""
    workspace = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}"
    try:
        shutil.rmtree(workspace, ignore_errors=True)
        logger.info(f"Cleaned workspace for scan {scan_id}")
    except Exception as e:
        logger.warning(f"Failed to clean workspace {scan_id}: {e}")


# --- Celery Tasks ---

@celery_app.task(bind=True, base=ScanTask)
def run_url_scan(self, scan_id: str, config: Dict[str, Any]):
    """
    Run a URL security scan.
    
    Args:
        scan_id: The scan ID
        config: Scan configuration with target_url, modules, etc.
    """
    target_url = config.get("target_url", "")
    modules = config.get("modules", ["recon", "web", "ssl", "network"])
    
    logger.info(f"Starting URL scan: scan_id={scan_id}, target={target_url}")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        results = loop.run_until_complete(
            _run_scan_pipeline(scan_id, "url", target_url, modules, config)
        )
        return results
    finally:
        loop.close()


@celery_app.task(bind=True, base=ScanTask)
def run_github_scan(self, scan_id: str, config: Dict[str, Any]):
    """
    Run a GitHub repository security scan.
    
    Args:
        scan_id: The scan ID
        config: Scan configuration with repo_url, branch, etc.
    """
    import os
    
    repo_url = config.get("repo_url", "")
    branch = config.get("branch", "main")
    github_token = config.get("github_token")
    modules = config.get("modules", ["sast", "secrets", "dependencies", "infrastructure", "ai_review"])
    
    logger.info(f"Starting GitHub scan: scan_id={scan_id}, repo={repo_url}")
    
    # Clone repository
    workspace = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}"
    clone_dir = f"{workspace}/repo"
    os.makedirs(clone_dir, exist_ok=True)
    
    try:
        from utils.git_utils import clone_repository
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(clone_repository(repo_url, clone_dir, branch, github_token))
            
            # Update config with cloned path
            config["file_path"] = clone_dir
            config["is_git_repo"] = True
            
            results = loop.run_until_complete(
                _run_scan_pipeline(scan_id, "github", clone_dir, modules, config)
            )
            return results
        finally:
            loop.close()
            
    except Exception as e:
        logger.exception(f"GitHub scan failed: {e}")
        # Bug #26 fixed: workspace was never cleaned up on clone failure,
        # leaking a directory under SCAN_WORKSPACE_DIR for every failed job.
        _cleanup_workspace(scan_id)
        raise


@celery_app.task(bind=True, base=ScanTask)
def run_upload_scan(self, scan_id: str, config: Dict[str, Any]):
    """
    Run a code upload scan.
    
    Args:
        scan_id: The scan ID
        config: Scan configuration with file_path, modules, etc.
    """
    file_path = config.get("file_path", "")
    modules = config.get("modules", ["sast", "secrets", "dependencies", "infrastructure", "ai_review"])
    
    logger.info(f"Starting upload scan: scan_id={scan_id}, file={file_path}")
    
    # Extract if zip
    import os
    if file_path.endswith(".zip"):
        extract_dir = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}/extracted"
        os.makedirs(extract_dir, exist_ok=True)
        
        import zipfile
        with zipfile.ZipFile(file_path, "r") as z:
            z.extractall(extract_dir)
        config["file_path"] = extract_dir
    elif file_path.endswith(".tar.gz") or file_path.endswith(".tgz"):
        extract_dir = f"{settings.SCAN_WORKSPACE_DIR}/{scan_id}/extracted"
        os.makedirs(extract_dir, exist_ok=True)
        
        import tarfile
        with tarfile.open(file_path, "r:gz") as t:
            t.extractall(extract_dir)
        config["file_path"] = extract_dir
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        results = loop.run_until_complete(
            _run_scan_pipeline(scan_id, "upload", config["file_path"], modules, config)
        )
        return results
    finally:
        loop.close()


@celery_app.task(bind=True, base=ScanTask)
def run_paste_scan(self, scan_id: str, config: Dict[str, Any]):
    """
    Run a raw code paste scan.
    
    Args:
        scan_id: The scan ID
        config: Scan configuration with code, language, etc.
    """
    file_path = config.get("file_path", "")
    modules = config.get("modules", ["sast", "ai_review"])
    
    logger.info(f"Starting paste scan: scan_id={scan_id}")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        results = loop.run_until_complete(
            _run_scan_pipeline(scan_id, "paste", file_path, modules, config)
        )
        return results
    finally:
        loop.close()


@celery_app.task(bind=True, base=ScanTask)
def run_api_endpoint_scan(self, scan_id: str, config: Dict[str, Any]):
    """
    Run an API endpoint security scan.
    
    Args:
        scan_id: The scan ID
        config: Scan configuration with base_url, spec, etc.
    """
    base_url = config.get("base_url", "")
    modules = config.get("modules", ["api_security"])
    
    logger.info(f"Starting API endpoint scan: scan_id={scan_id}, target={base_url}")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        results = loop.run_until_complete(
            _run_scan_pipeline(scan_id, "api_endpoint", base_url, modules, config)
        )
        return results
    finally:
        loop.close()
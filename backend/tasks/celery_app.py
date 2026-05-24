# ============================================
# SentinelAI - Celery Application
# ============================================
"""
Celery application configuration with Redis broker.
Supports task routing, result backend, and scheduled tasks.
"""

import logging
import os

from celery import Celery
from celery.signals import task_failure, task_success, task_retry
from config import settings

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "sentinelai",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["tasks.scan_tasks"],
)

# Celery configuration
celery_app.conf.update(
    # Serialization
    task_serializer=settings.CELERY_TASK_SERIALIZER,
    accept_content=settings.CELERY_ACCEPT_CONTENT,
    result_serializer=settings.CELERY_RESULT_SERIALIZER,
    
    # Timezone
    timezone=settings.CELERY_TIMEZONE,
    enable_utc=settings.CELERY_ENABLE_UTC,
    
    # Task tracking
    task_track_started=settings.CELERY_TASK_TRACK_STARTED,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT,
    
    # Worker settings
    worker_prefetch_multiplier=1,  # Process one task at a time per worker
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks
    
    # Result settings
    result_expires=86400,  # Results expire after 24 hours
    result_extended=True,
    
    # Broker settings
    broker_connection_retry_on_startup=True,
    broker_heartbeat=60,
    
    # Task routes
    task_routes={
        "tasks.scan_tasks.run_url_scan": {"queue": "scans"},
        "tasks.scan_tasks.run_github_scan": {"queue": "scans"},
        "tasks.scan_tasks.run_upload_scan": {"queue": "scans"},
        "tasks.scan_tasks.run_paste_scan": {"queue": "scans"},
        "tasks.scan_tasks.run_api_endpoint_scan": {"queue": "scans"},
    },
    
    # Task annotations
    task_annotations={
        "*": {
            "bind": True,
        }
    },
    
    # RedBeat for scheduled tasks (if enabled)
    redbeat_redis_url=settings.CELERY_BROKER_URL,
    beat_scheduler="redbeat.RedBeatScheduler",
    beat_max_loop_interval=300,
)


# --- Celery Signals ---

@task_failure.connect
def handle_task_failure(sender=None, task_id=None, exception=None, args=None, kwargs=None, **extras):
    """Handle task failure - log and update database."""
    logger.error(f"Task {task_id} failed: {exception}")
    
    # Try to update scan status
    try:
        if args and len(args) > 0:
            scan_id = args[0]
            from database import async_session_maker
            from models.scan import Scan
            import asyncio
            
            async def update_scan():
                async with async_session_maker() as session:
                    result = await session.execute(
                        __import__("sqlalchemy", fromlist=["select"]).select(Scan).where(Scan.id == scan_id)
                    )
                    scan = result.scalar_one_or_none()
                    if scan:
                        scan.status = "failed"
                        scan.error_message = str(exception)
                        await session.commit()
            
            try:
                # Bug #9 fixed: asyncio.create_task() cannot be called from a
                # synchronous Celery signal handler (fire-and-forget with no
                # guarantee the coroutine runs before the worker exits).
                # Use a fresh event loop that we own and explicitly close.
                from sqlalchemy import select
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(update_scan())
                finally:
                    loop.close()
            except Exception as e:
                logger.warning(f"Failed to update scan status: {e}")
    except Exception:
        pass


@task_success.connect
def handle_task_success(sender=None, result=None, **kwargs):
    """Handle task success."""
    logger.info(f"Task {sender.request.id} completed successfully")


@task_retry.connect
def handle_task_retry(sender=None, request=None, reason=None, **kwargs):
    """Handle task retry."""
    logger.warning(f"Task {request.id} retrying: {reason}")


# --- Health Check ---

@celery_app.task(bind=True)
def health_check(self):
    """Health check task."""
    return {"status": "ok", "worker": self.request.hostname}


def start_worker():
    """Start a Celery worker programmatically."""
    celery_app.worker_main([
        "worker",
        "--loglevel=info",
        "--concurrency=2",
        "--queues=scans,default",
    ])


if __name__ == "__main__":
    start_worker()
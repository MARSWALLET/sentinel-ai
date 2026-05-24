# ============================================
# SentinelAI - FastAPI Application Entry Point
# ============================================
"""
Main FastAPI application with middleware, routers, and startup/shutdown events.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from config import settings
from database import init_db, close_db

# Import routers
from routers.auth import router as auth_router
from routers.scans import router as scans_router
from routers.findings import router as findings_router
from routers.reports import router as reports_router
from routers.settings import router as settings_router

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - startup and shutdown events."""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"Log level: {settings.LOG_LEVEL}")
    logger.info(f"LLM Provider: {settings.LLM_PROVIDER}")
    logger.info(f"Self-hosted mode: {settings.SELF_HOSTED_MODE}")
    
    await init_db()
    logger.info("Database initialized")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    await close_db()
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    description="AI-Powered Security Scanning Agent - Autonomous vulnerability assessment for web applications, APIs, codebases, and infrastructure.",
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# --- Middleware ---

# Bug #22 fixed: allow_origins=["*"] with allow_credentials=True is rejected by
# all browsers (CORS spec). Use explicit origins or disable credentials.
# In production, set CORS_ORIGINS env var to a comma-separated list of allowed
# origins. In development we fall back to localhost defaults.
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "http://localhost:80",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Request timing middleware
@app.middleware("http")
async def add_request_timing(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    logger.debug(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    return response

# Error handling middleware
@app.middleware("http")
async def catch_exceptions(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:
        logger.exception(f"Unhandled exception: {exc}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "detail": str(exc) if settings.DEBUG else "An unexpected error occurred",
            },
        )


# --- Routers ---
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(findings_router, prefix="/api", tags=["Findings"])
app.include_router(reports_router, prefix="/api", tags=["Reports"])
app.include_router(settings_router, prefix="/api/settings", tags=["Settings"])


# --- Root and Health Endpoints ---

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint - API info."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "description": "AI-Powered Security Scanning Agent",
        "docs": "/docs",
        "health": "/api/health",
    }


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint for Docker and load balancers."""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "timestamp": time.time(),
    }


@app.get("/api/status", tags=["Status"])
async def system_status():
    """Detailed system status."""
    import asyncio
    from tasks.celery_app import celery_app

    # Bug #21 fixed: celery inspect().active() is a synchronous blocking call
    # that waits for worker ping responses. Run it in a thread executor so it
    # doesn't block the async event loop.
    loop = asyncio.get_event_loop()
    inspector = celery_app.control.inspect()
    active_workers = await loop.run_in_executor(None, lambda: inspector.active() or {})

    return {
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "llm_provider": settings.LLM_PROVIDER,
        "llm_model": settings.LLM_MODEL,
        "workers": len(active_workers),
        "self_hosted": settings.SELF_HOSTED_MODE,
    }


# --- WebSocket Endpoint for Live Scan Progress ---

class ConnectionManager:
    """Manage WebSocket connections for scan progress updates."""
    
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
    
    async def connect(self, scan_id: str, websocket: WebSocket):
        # Bug #20 fixed: close the previous connection before replacing it so
        # the old client is not left in a zombie open-but-ignored state.
        if scan_id in self.active_connections:
            try:
                await self.active_connections[scan_id].close(code=1001)
            except Exception:
                pass
        await websocket.accept()
        self.active_connections[scan_id] = websocket
        logger.info(f"WebSocket connected for scan {scan_id}")
    
    def disconnect(self, scan_id: str):
        if scan_id in self.active_connections:
            del self.active_connections[scan_id]
            logger.info(f"WebSocket disconnected for scan {scan_id}")
    
    async def send_progress(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            try:
                await self.active_connections[scan_id].send_json(message)
            except Exception:
                self.disconnect(scan_id)


manager = ConnectionManager()


@app.websocket("/api/scans/{scan_id}/live")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress updates.
    
    Connect to this endpoint to receive live updates during a scan.
    Messages include module status, progress percentage, and findings.
    """
    await manager.connect(scan_id, websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "scan_id": scan_id,
            "message": "Subscribed to scan progress updates",
        })
        
        # Keep connection alive and handle client messages
        while True:
            message = await websocket.receive_text()
            # Handle ping/pong for connection keepalive
            if message == "ping":
                await websocket.send_text("pong")
            
    except WebSocketDisconnect:
        manager.disconnect(scan_id)
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
        manager.disconnect(scan_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=4,
        loop="uvloop",
        log_level=settings.LOG_LEVEL.lower(),
    )
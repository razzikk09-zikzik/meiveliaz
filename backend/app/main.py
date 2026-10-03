# MEYVIZHI FastAPI backend — application entry point.
# Security: CORS allow-list, per-IP rate limiting, request size limit,
# structured logging. Secrets live only in environment variables (.env).
import asyncio
import time
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import settings
from .routes import analyze, auth, reports, threats
from .utils.logging import configure_logging, get_logger, log_event

configure_logging()
logger = get_logger("meyvizhi.main")

app = FastAPI(
    title="MEYVIZHI API",
    description="Scam detection and cyber-intelligence backend for MEYVIZHI.",
    version="0.1.0",
)

# --- CORS (spec section 20): configurable allow-list, never wildcard by default.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- Per-IP sliding-window rate limiter (spec section 21).
_RATE_BUCKET = defaultdict(deque)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    started = time.perf_counter()

    # Request size limit
    content_length = int(request.headers.get("content-length", 0) or 0)
    if content_length > settings.max_body_bytes:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)

    # Rate limit (skip health checks)
    if request.url.path not in ("/health", "/api/health"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = _RATE_BUCKET[client_ip]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= settings.rate_limit_per_minute:
            log_event(logger, "rate_limited", ip=client_ip, request_id=request_id)
            return JSONResponse({"detail": "Too many requests — try again in a minute"}, status_code=429)
        bucket.append(now)

    request.state.request_id = request_id
    response = await call_next(request)
    duration = time.perf_counter() - started
    response.headers["X-Request-ID"] = request_id
    log_event(logger, "request", request_id=request_id, method=request.method,
              path=request.url.path, status=response.status_code, duration=f"{duration:.2f}s")
    return response


@app.get("/health")
async def health():
    """Deployment health check (spec section 5)."""
    return {"status": "ok"}


@app.get("/api/config-status")
async def config_status():
    """Provider configuration check — YES/NO only, never secret values (spec 25)."""
    return {
        "gemini_configured": "YES" if settings.gemini_configured else "NO",
        "virustotal_configured": "YES" if settings.virustotal_configured else "NO",
        "neo4j_configured": "YES" if settings.neo4j_configured else "NO",
        "supabase_configured": "YES" if settings.supabase_configured else "NO",
    }


app.include_router(analyze.router)
app.include_router(reports.router)
app.include_router(threats.router)
app.include_router(auth.router)


@app.on_event("startup")
async def _startup() -> None:
    log_event(
        logger, "backend_started",
        gemini=settings.gemini_configured,
        virustotal=settings.virustotal_configured,
        neo4j=settings.neo4j_configured,
        supabase=settings.supabase_configured,
    )


# Local development entry: uvicorn app.main:app --reload
# Production start command listens on 0.0.0.0 with the platform PORT (spec 27).
if __name__ == "__main__":
    import os

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
    )

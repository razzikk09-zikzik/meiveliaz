# Supabase/PostgreSQL persistence (spec section 11) — implemented over
# Supabase's REST interfaces (PostgREST + Auth) using httpx, so no SDK is
# required. Every failure returns None/False so callers degrade gracefully.
import httpx

from ..config import settings
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.supabase")


def _headers(jwt: str | None = None, admin: bool = False) -> dict:
    key = settings.supabase_service_role_key if (admin and settings.supabase_admin_configured) else settings.supabase_anon_key
    headers = {"apikey": key, "Content-Type": "application/json"}
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    else:
        headers["Authorization"] = f"Bearer {key}"
    return headers


async def insert_report(report: dict) -> dict | None:
    """Insert a report row; returns the stored row or None."""
    if not settings.supabase_admin_configured:
        return None
    url = f"{settings.supabase_url}/rest/v1/reports"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                url, json=report, headers=_headers(admin=True),
                params={"select": "*"},
            )
            if resp.status_code not in (200, 201):
                log_event(logger, "supabase_insert_failed", status=resp.status_code)
                return None
            return resp.json()[0] if resp.json() else None
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "supabase_error", error=type(exc).__name__)
        return None


async def list_reports(limit: int = 100, jwt: str | None = None) -> list | None:
    if not settings.supabase_configured:
        return None
    url = f"{settings.supabase_url}/rest/v1/reports"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                url, headers=_headers(jwt=jwt),
                params={"select": "*", "order": "created_at.desc", "limit": limit},
            )
            if resp.status_code != 200:
                log_event(logger, "supabase_list_failed", status=resp.status_code)
                return None
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "supabase_error", error=type(exc).__name__)
        return None


async def recent_reports(days: int = 7, limit: int = 200) -> list | None:
    """Reports from the last N days — used by the threats aggregation."""
    if not settings.supabase_admin_configured:
        return None
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    url = f"{settings.supabase_url}/rest/v1/reports"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                url, headers=_headers(admin=True),
                params={"select": "*", "created_at": f"gte.{since}", "order": "created_at.desc", "limit": limit},
            )
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "supabase_error", error=type(exc).__name__)
        return None


async def login(email: str, password: str) -> dict | None:
    """Analyst sign-in through Supabase Auth (GoTrue)."""
    if not settings.supabase_configured:
        return None
    url = f"{settings.supabase_url}/auth/v1/token?grant_type=password"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                url, json={"email": email, "password": password},
                headers={"apikey": settings.supabase_anon_key, "Content-Type": "application/json"},
            )
            if resp.status_code != 200:
                log_event(logger, "supabase_login_failed", status=resp.status_code)
                return None
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "supabase_error", error=type(exc).__name__)
        return None


async def verify_jwt(jwt: str) -> dict | None:
    """Validate an analyst JWT; returns the user or None."""
    if not settings.supabase_configured or not jwt:
        return None
    url = f"{settings.supabase_url}/auth/v1/user"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers=_headers(jwt=jwt))
            if resp.status_code != 200:
                return None
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "supabase_error", error=type(exc).__name__)
        return None

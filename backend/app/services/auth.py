# Analyst authentication dependency (spec section 12).
# The backend itself verifies the Supabase JWT — hiding UI elements in React
# is never the security boundary.
from fastapi import HTTPException, Request

from . import supabase_service
from ..config import settings
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.auth")


async def require_analyst(request: Request) -> dict:
    """Dependency for protected endpoints. Verifies Authorization: Bearer <jwt>
    against Supabase Auth. 401 when the token is missing/invalid, 503 when
    Supabase is not configured (with a token present)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    jwt = auth_header.removeprefix("Bearer ").strip()
    if not jwt:
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    if not settings.supabase_configured:
        raise HTTPException(status_code=503, detail="Analyst authentication is not configured yet")

    user = await supabase_service.verify_jwt(jwt)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    log_event(logger, "analyst_authorized", user_id=user.get("id", "?")[:8])
    return {"user": user, "jwt": jwt}

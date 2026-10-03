# POST /api/auth/login — analyst sign-in (spec section 12).
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..config import settings
from ..services import supabase_service
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> dict:
    if "@" not in body.email or not body.password:
        raise HTTPException(status_code=422, detail="Provide a valid email and password")
    if not settings.supabase_configured:
        # Friendly degradation — do not crash, tell the operator what to do.
        raise HTTPException(
            status_code=503,
            detail="Analyst login is not configured yet. Set SUPABASE_URL and SUPABASE_ANON_KEY on the backend.",
        )
    session = await supabase_service.login(body.email, body.password)
    if not session or not session.get("access_token"):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    log_event(logger, "analyst_login", email_domain=body.email.split("@")[-1])
    return {
        "access_token": session["access_token"],
        "token_type": "bearer",
        "user": session.get("user", {}),
    }

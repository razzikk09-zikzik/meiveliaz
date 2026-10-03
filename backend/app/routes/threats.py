# GET /api/threats (spec section 17).
# Aggregates real reports when Supabase is configured; otherwise serves
# clearly-marked seed/demo data so the app works before accounts exist.
from collections import Counter

from fastapi import APIRouter

from ..schemas.report import Alert, Threat, ThreatsResponse
from ..services import supabase_service
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.threats")
router = APIRouter(prefix="/api", tags=["threats"])

# --- Seed/demo data (spec section 17) — replaced by real aggregation when
# --- Supabase is configured and contains reports.
SEED_THREATS = [
    Threat(
        id="seed-campaign-velachery",
        title="Active scam campaign",
        category="Bank KYC",
        area="Velachery",
        reports=14,
        risk="HIGH",
        description="14 reports this week",
    ),
    Threat(
        id="seed-bank-kyc-adyar",
        title="Bank KYC Impersonation",
        category="Bank KYC",
        area="Adyar",
        reports=8,
        risk="HIGH",
        description="Fake bank messages asking for OTP",
    ),
    Threat(
        id="seed-courier-sholinganallur",
        title="Courier Refund Scam",
        category="Courier",
        area="Sholinganallur",
        reports=5,
        risk="MEDIUM",
        description="Fake delivery links asking for payment",
    ),
]

SEED_ALERTS = [
    Alert(
        id="alert-velachery-campaign",
        title="Active scam campaign reported",
        detail="in Velachery, 14 reports this week.",
        area="Velachery",
        reports=14,
        risk="HIGH",
    ),
]


def _aggregate(rows: list) -> tuple:
    """Group recent reports into (threats, alerts)."""
    by_area = Counter()
    by_area_category = Counter()
    for row in rows:
        area = (row.get("location") or "Unknown").strip() or "Unknown"
        category = (row.get("category") or "Other").strip() or "Other"
        by_area[area] += 1
        by_area_category[(area, category)] += 1

    threats, alerts = [], []
    top_area, top_count = (by_area.most_common(1) or [("Unknown", 0)])[0]
    if top_count:
        alerts.append(Alert(
            id="agg-top-campaign",
            title="Active scam campaign reported",
            detail=f"in {top_area}, {top_count} reports this week.",
            area=top_area,
            reports=top_count,
            risk="HIGH" if top_count >= 5 else "MEDIUM",
        ))
    for (area, category), count in by_area_category.most_common(10):
        threats.append(Threat(
            id=f"agg-{area}-{category}".lower().replace(" ", "-"),
            title=category,
            category=category,
            area=area,
            reports=count,
            risk="HIGH" if count >= 5 else ("MEDIUM" if count >= 3 else "LOW"),
        ))
    return threats, alerts


@router.get("/threats", response_model=ThreatsResponse)
async def get_threats() -> dict:
    rows = await supabase_service.recent_reports(days=7) if settings_ready() else None
    if rows:
        threats, alerts = _aggregate(rows)
        if threats:
            log_event(logger, "threats_from_supabase", count=len(threats))
            return ThreatsResponse(source="supabase", threats=threats, alerts=alerts).model_dump()
    log_event(logger, "threats_from_seed", count=len(SEED_THREATS))
    return ThreatsResponse(
        source="seed",
        threats=SEED_THREATS,
        alerts=SEED_ALERTS,
    ).model_dump()


def settings_ready() -> bool:
    from ..config import settings
    return settings.supabase_admin_configured

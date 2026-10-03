# POST /api/reports (anonymous, spec section 16) and analyst-only
# GET /api/reports (spec section 12 — backend-enforced authentication).
import uuid

from fastapi import APIRouter, Depends, HTTPException

from ..schemas.report import ReportCreate, ReportOut
from ..services import neo4j_service, supabase_service
from ..services.auth import require_analyst
from ..utils import text_utils, url_utils
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.reports")
router = APIRouter(prefix="/api", tags=["reports"])


@router.post("/reports", response_model=ReportOut, status_code=201)
async def create_report(report: ReportCreate) -> dict:
    report_id = str(uuid.uuid4())
    domains = url_utils.extract_urls(report.message or "") or ([report.url] if report.url else [])
    record = {
        "id": report_id,
        "category": report.scam_type,
        "message": report.message,
        "url": report.url,
        "phone": report.phone,
        "upi_id": report.upi_id,
        "location": report.location,
        "money_lost": report.money_lost,
        "anonymous": report.anonymous,
        "risk_level": "UNASSESSED",
    }

    stored_row = await supabase_service.insert_report(record)
    stored = stored_row is not None

    graph_indexed = False
    try:
        graph_indexed = await neo4j_service.index_report({
            "id": report_id,
            "category": report.scam_type,
            "location": report.location,
            "risk": "UNASSESSED",
            "message": report.message,
            "phones": text_utils.extract_phones(report.message or ""),
            "domains": [url_utils.domain_of(u) for u in domains if url_utils.domain_of(u)],
            "upi_ids": text_utils.extract_upi_ids(report.message or ""),
        })
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "graph_index_error", error=type(exc).__name__)

    log_event(logger, "report_created", stored=stored, graph_indexed=graph_indexed, category=report.scam_type)

    note = "Report stored."
    if not stored:
        note = "Report received, but secure storage is not configured yet — the report was not persisted."
    return {
        "id": report_id,
        "stored": stored,
        "graph_indexed": graph_indexed,
        "message": note,
    }


@router.get("/reports")
async def get_reports(analyst: dict = Depends(require_analyst)) -> dict:
    """Analyst-only: list reports. Unauthenticated callers get 401 (spec 12)."""
    rows = await supabase_service.list_reports(jwt=analyst.get("jwt"))
    if rows is None:
        raise HTTPException(status_code=503, detail="Report storage is not configured yet")
    return {"reports": rows, "count": len(rows)}

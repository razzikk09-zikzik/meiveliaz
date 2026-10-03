# Neo4j scam-relationship intelligence (spec section 10).
# Nodes: (:Report)-[:HAS_PHONE|HAS_DOMAIN|HAS_UPI|LOCATED_IN]->entities, (:Report)-[:PART_OF]->(:Campaign)
# Implemented over the Neo4j HTTP Query API (Neo4j 5.19+ / Aura), so no heavy
# driver dependency is required. Any failure returns {"available": false}.
import uuid
from datetime import datetime, timezone

import httpx

from ..config import settings
from ..utils.logging import get_logger, log_event
from ..utils import text_utils, url_utils

logger = get_logger("meyvizhi.neo4j")


def _http_endpoint() -> str:
    """neo4j+s://abc.databases.neo4j.io -> https://abc.databases.neo4j.io/db/neo4j/query/v2"""
    raw = settings.neo4j_uri
    for scheme in ("neo4j+s://", "neo4j+ssc://", "bolt+s://", "bolt://", "neo4j://"):
        if raw.startswith(scheme):
            host = raw[len(scheme):].strip("/")
            return f"https://{host}/db/neo4j/query/v2"
    return f"https://{raw.strip('/').replace('https://', '')}/db/neo4j/query/v2"


def _auth() -> tuple:
    return (settings.neo4j_username or "neo4j", settings.neo4j_password)


async def _run(statement: str, parameters: dict | None = None) -> dict | None:
    """Execute one Cypher statement. Returns {"records": [...]} or None on failure."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                _http_endpoint(),
                json={"statement": statement, "parameters": parameters or {}},
                auth=_auth(),
            )
            if resp.status_code != 200:
                log_event(logger, "neo4j_unavailable", status=resp.status_code)
                return None
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "neo4j_error", error=type(exc).__name__)
        return None


async def _query_available() -> bool:
    result = await _run("RETURN 1 AS ok")
    return result is not None


async def index_report(report: dict) -> bool:
    """Create :Report node + entity relationships for a submitted report."""
    if not settings.neo4j_configured:
        return False
    report_id = report.get("id") or str(uuid.uuid4())
    phones = report.get("phones") or (text_utils.extract_phones(report.get("message", "")) if report.get("message") else [])
    domains = report.get("domains") or []
    upi_ids = report.get("upi_ids") or []
    location = report.get("location") or "Unknown"

    # Version-safe formulation: link each entity type separately.
    base = "MERGE (r:Report {id: $id}) SET r.category=$category, r.location=$location, r.risk=$risk, r.created_at=$created_at\n"
    ok = await _run(base + "RETURN count(r) AS c", {
        "id": report_id, "category": report.get("category", ""),
        "location": location, "risk": report.get("risk", ""), "created_at": datetime.now(timezone.utc).isoformat(),
    })
    if ok is None:
        return False
    for label, rel, values in (("Phone", "HAS_PHONE", phones), ("Domain", "HAS_DOMAIN", domains), ("UPI", "HAS_UPI", upi_ids)):
        for value in values[:10]:
            await _run(
                f"MATCH (r:Report {{id: $id}}) MERGE (e:{label} {{value: $value}}) MERGE (r)-[:{rel}]->(e)",
                {"id": report_id, "value": value},
            )
    if location:
        await _run(
            "MATCH (r:Report {id: $id}) MERGE (l:Location {name: $loc}) MERGE (r)-[:LOCATED_IN]->(l)",
            {"id": report_id, "loc": location},
        )
    log_event(logger, "neo4j_report_indexed", report_id=report_id)
    return True


async def find_related(message: str = "", url: str = "") -> dict:
    """Find related scam activity through shared phone/domain/UPI entities."""
    if not settings.neo4j_configured:
        return {"available": False, "reason": "NEO4J_* not set"}
    if not await _query_available():
        return {"available": False, "reason": "graph unreachable"}

    domains = [url_utils.domain_of(u) for u in url_utils.extract_urls(message or "") if url_utils.domain_of(u)]
    if url:
        d = url_utils.domain_of(url)
        if d:
            domains.append(d)
    phones = text_utils.extract_phones(message or "")
    upi_ids = text_utils.extract_upi_ids(message or "")
    values = domains + phones + upi_ids
    if not values:
        # Nothing to correlate — do not add a meaningless signal.
        return {"available": True, "neutral": True, "related_reports": 0}

    result = await _run(
        """
MATCH (e)-[:HAS_PHONE|HAS_DOMAIN|HAS_UPI]-(r2:Report)
WHERE e.value IN $values
RETURN count(DISTINCT r2) AS related,
       collect(DISTINCT r2.category)[0..5] AS categories,
       collect(DISTINCT r2.location)[0..5] AS locations
""",
        {"values": values},
    )
    if result is None:
        return {"available": False, "reason": "query failed"}
    try:
        row = result["records"][0]
        related = int(row.get("related", 0))
        if related == 0:
            return {"available": True, "neutral": True, "related_reports": 0}
        # Community evidence raises risk, capped below Gemini/heuristic range.
        score = min(80, 45 + related * 10)
        return {
            "available": True,
            "score": score,
            "related_reports": related,
            "categories": row.get("categories", []),
            "locations": row.get("locations", []),
        }
    except (KeyError, IndexError, TypeError, ValueError):
        return {"available": False, "reason": "unexpected graph response"}

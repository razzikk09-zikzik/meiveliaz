# VirusTotal URL reputation signal (spec section 9).
# Free API is heavily rate-limited: every failure path returns
# {"available": false} and never breaks the analysis. Simple in-memory cache.
import time

import httpx

from ..config import settings
from ..utils.logging import get_logger, log_event
from ..utils.url_utils import virustotal_url_id

logger = get_logger("meyvizhi.virustotal")

_CACHE = {}  # url_id -> {"expires": epoch, "data": {...}}
CACHE_TTL_SECONDS = 3600


def _cached(url_id: str):
    entry = _CACHE.get(url_id)
    if entry and entry["expires"] > time.time():
        return entry["data"]
    if entry:
        _CACHE.pop(url_id, None)
    return None


def _store(url_id: str, data: dict) -> None:
    if len(_CACHE) > 500:
        _CACHE.clear()
    _CACHE[url_id] = {"expires": time.time() + CACHE_TTL_SECONDS, "data": data}


async def analyze_url(url: str) -> dict:
    if not settings.virustotal_configured:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY not set"}

    url_id = virustotal_url_id(url)
    hit = _cached(url_id)
    if hit:
        return hit

    headers = {"x-apikey": settings.virustotal_api_key}
    base = "https://www.virustotal.com/api/v3"
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(f"{base}/urls/{url_id}", headers=headers)
            if resp.status_code == 404:
                # Not in VT corpus yet — submit for future analyses, no verdict now.
                await client.post(f"{base}/urls", headers=headers, data={"url": url})
                log_event(logger, "virustotal_submitted", reason="not_found")
                return {"available": False, "reason": "URL not in VirusTotal yet; submitted"}
            if resp.status_code == 429:
                log_event(logger, "virustotal_rate_limited")
                return {"available": False, "reason": "rate limited"}
            if resp.status_code != 200:
                log_event(logger, "virustotal_unavailable", status=resp.status_code)
                return {"available": False, "reason": f"HTTP {resp.status_code}"}
            data = resp.json()

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))

        if malicious > 0:
            score = min(95, 70 + malicious * 5)
        elif suspicious > 0:
            score = 55
        else:
            score = 15

        result = {
            "available": True,
            "score": score,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "signal": "MALICIOUS_REPUTATION" if malicious > 0 else ("SUSPICIOUS_REPUTATION" if suspicious > 0 else "CLEAN_REPUTATION"),
        }
        _store(url_id, result)
        return result
    except (httpx.TimeoutException, httpx.HTTPError) as exc:
        log_event(logger, "virustotal_error", error=type(exc).__name__)
        return {"available": False, "reason": "request failed"}
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "virustotal_error", error=type(exc).__name__)
        return {"available": False, "reason": "unexpected error"}

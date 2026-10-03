# Gemini AI analysis signal (spec section 7).
# One of several signals — never the sole decision-maker. If the key is
# missing or the API fails, returns {"available": false} and analysis continues.
import httpx

from ..config import settings
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.gemini")

PROMPT = """You are a scam-detection analyst for MEYVIZHI, an app protecting people in South Chennai, India.
Analyze the following message (it may be English, Tamil, Tanglish or a mix) for scam indicators:
scam intent, phishing, impersonation of banks/government/companies, urgency pressure, requests for OTP/PIN/CVV,
payment requests, social engineering, suspicious instructions, suspicious domain naming.

Respond ONLY with JSON in exactly this shape:
{"risk_score": <int 0-100>, "classification": "SAFE"|"SUSPICIOUS"|"SCAM", "confidence": <float 0-1>,
 "signals": ["<short signal name>", ...], "explanation": "<one or two sentences>"}

Message to analyze:
"""


async def analyze(text: str, language: str = "english") -> dict:
    if not settings.gemini_configured:
        return {"available": False, "reason": "GEMINI_API_KEY not set"}

    payload = {
        "contents": [{"parts": [{"text": PROMPT + text}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 512,
        },
    }
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
    )
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                log_event(logger, "gemini_unavailable", status=resp.status_code)
                return {"available": False, "reason": f"HTTP {resp.status_code}"}
            data = resp.json()
        raw = data["candidates"][0]["content"]["parts"][0]["text"]
        import json
        parsed = json.loads(raw)
        risk_score = max(0, min(100, int(parsed.get("risk_score", 0))))
        return {
            "available": True,
            "score": risk_score,
            "classification": str(parsed.get("classification", "SUSPICIOUS")).upper(),
            "confidence": float(parsed.get("confidence", 0.5)),
            "signals": parsed.get("signals", []),
            "explanation": str(parsed.get("explanation", ""))[:400],
        }
    except Exception as exc:  # noqa: BLE001 — never crash analysis on provider failure
        log_event(logger, "gemini_error", error=type(exc).__name__)
        return {"available": False, "reason": "request failed"}

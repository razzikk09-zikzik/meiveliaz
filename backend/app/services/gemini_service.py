# Gemini AI analysis signal (spec section 7).
# One of several signals — never the sole decision-maker. If the key is
# missing or the API fails, returns {"available": false} and analysis continues.
import base64
import json

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

IMAGE_PROMPT = """You are a scam-detection analyst for MEYVIZHI, an app protecting people in South Chennai, India.
The attached image is a screenshot (SMS, WhatsApp chat, email, website or payment screen) that a user wants checked.
Analyze every visible element: sender, message text, links, phone numbers, UPI IDs, QR codes, payment requests, urgency, impersonation.
The text may be in Tamil, English or Tanglish.

Respond ONLY with JSON in exactly this shape:
{"transcribed_text": "<transcribe ALL visible text exactly as shown>",
 "risk_score": <int 0-100>, "classification": "SAFE"|"SUSPICIOUS"|"SCAM", "confidence": <float 0-1>,
 "signals": ["<short signal name>", ...], "explanation": "<one or two sentences>"}
"""


def _endpoint() -> str:
    return (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.gemini_model}:generateContent?key={settings.gemini_api_key}"
    )


async def _generate(payload: dict, timeout: float = 30.0) -> dict | None:
    """Shared call helper. Returns parsed JSON or None on any failure."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(_endpoint(), json=payload)
            if resp.status_code != 200:
                log_event(logger, "gemini_unavailable", status=resp.status_code)
                return None
            raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(raw)
    except Exception as exc:  # noqa: BLE001 — never crash analysis on provider failure
        log_event(logger, "gemini_error", error=type(exc).__name__)
        return None


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
    parsed = await _generate(payload, timeout=30.0)
    if parsed is None:
        return {"available": False, "reason": "request failed"}

    return {
        "available": True,
        "score": max(0, min(100, int(parsed.get("risk_score", 0)))),
        "classification": str(parsed.get("classification", "SUSPICIOUS")).upper(),
        "confidence": float(parsed.get("confidence", 0.5)),
        "signals": parsed.get("signals", []),
        "explanation": str(parsed.get("explanation", ""))[:400],
    }


async def analyze_image(image_bytes: bytes, mime_type: str = "image/png") -> dict:
    """Analyze a screenshot with Gemini vision (spec section 18)."""
    if not settings.gemini_configured:
        return {"available": False, "reason": "GEMINI_API_KEY not set"}

    payload = {
        "contents": [{"parts": [
            {"text": IMAGE_PROMPT},
            {"inline_data": {"mime_type": mime_type, "data": base64.b64encode(image_bytes).decode()}},
        ]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
            "maxOutputTokens": 1024,
        },
    }
    parsed = await _generate(payload, timeout=45.0)
    if parsed is None:
        return {"available": False, "reason": "request failed"}

    return {
        "available": True,
        "score": max(0, min(100, int(parsed.get("risk_score", 0)))),
        "classification": str(parsed.get("classification", "SUSPICIOUS")).upper(),
        "confidence": float(parsed.get("confidence", 0.5)),
        "signals": parsed.get("signals", []),
        "explanation": str(parsed.get("explanation", ""))[:400],
        "transcribed_text": str(parsed.get("transcribed_text", ""))[:3000],
    }

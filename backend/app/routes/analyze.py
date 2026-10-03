# POST /api/analyze and POST /api/analyze/image (spec sections 14, 18).
from fastapi import APIRouter, File, HTTPException, UploadFile

from ..schemas.analyze import AnalyzeRequest, AnalyzeResponse
from ..services import (
    gemini_service,
    heuristic_engine,
    neo4j_service,
    risk_engine,
    virustotal_service,
)
from ..utils import text_utils, url_utils
from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.analyze")
router = APIRouter(prefix="/api", tags=["analyze"])


async def _build_verdict(text: str, gemini: dict) -> dict:
    """Run heuristics (+ blocklists), VirusTotal and the graph on `text`,
    then fuse everything in the risk engine."""
    heuristics = heuristic_engine.analyze(text)
    urls = heuristics.get("urls") or []

    async def _none():
        return {"available": False, "reason": "no URL in message"}

    vt_task = virustotal_service.analyze_url(urls[0]) if urls else _none()
    graph_task = neo4j_service.find_related(message=text)
    virustotal, graph = await vt_task, await graph_task

    verdict = risk_engine.combine(gemini, heuristics, virustotal, graph)
    verdict["urls"] = urls
    verdict["extracted"] = {
        "phones": text_utils.extract_phones(text),
        "upi_ids": text_utils.extract_upi_ids(text),
        "domains": [url_utils.domain_of(u) for u in urls if url_utils.domain_of(u)],
        "languages": ["tamil"] if text_utils.has_tamil(text) else ["english"],
    }
    return verdict


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> dict:
    gemini = await gemini_service.analyze(request.text, request.language)
    verdict = await _build_verdict(request.text, gemini)
    log_event(
        logger, "analysis_completed",
        classification=verdict["classification"],
        risk=verdict["risk_score"],
        providers=",".join(k for k, v in verdict["sources"].items() if v),
    )
    return verdict


@router.post("/analyze/image", response_model=AnalyzeResponse)
async def analyze_image(image: UploadFile = File(...)) -> dict:
    """Screenshot analysis: Gemini vision first, Tesseract OCR as fallback
    (spec section 18)."""
    from ..services import ocr_service

    if not (image.content_type or "").startswith("image/"):
        raise HTTPException(status_code=415, detail="Upload an image file (png/jpg/webp)")
    image_bytes = await image.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty upload")

    mime = image.content_type or "image/png"
    gemini_img = await gemini_service.analyze_image(image_bytes, mime)
    ocr = ocr_service.extract_text(image_bytes)

    text = (gemini_img.get("transcribed_text") or "").strip() or (ocr.get("text") or "").strip()
    if not text and gemini_img.get("available"):
        # Vision returned a verdict even though no readable text was found
        # (e.g. a QR code or payment screen) — trust it.
        text = "(image contained no readable text)"
    if not text:
        raise HTTPException(
            status_code=503,
            detail="Could not read the image with AI vision or OCR — paste the message text instead",
        )

    gemini_provider = gemini_img if gemini_img.get("available") else {"available": False}
    verdict = await _build_verdict(text, gemini_provider)
    verdict["extracted"]["ocr_text"] = text[:1000]
    log_event(logger, "image_analysis_completed",
              classification=verdict["classification"],
              providers=",".join(k for k, v in verdict["sources"].items() if v))
    return verdict

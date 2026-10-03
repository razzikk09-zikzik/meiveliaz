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


async def _run_pipeline(text: str, url_hint: str = "", language: str = "english") -> dict:
    urls = url_utils.extract_urls(text)
    if url_hint and url_hint not in urls:
        urls.append(url_hint)

    heuristics = heuristic_engine.analyze(text)

    gemini_task = gemini_service.analyze(text, language)
    vt_task = virustotal_service.analyze_url(urls[0]) if urls else _none_provider()
    graph_task = neo4j_service.find_related(message=text, url=url_hint)
    gemini, virustotal, graph = await gemini_task, await vt_task, await graph_task

    verdict = risk_engine.combine(gemini, heuristics, virustotal, graph)
    verdict["urls"] = urls
    verdict["extracted"] = {
        "phones": text_utils.extract_phones(text),
        "upi_ids": text_utils.extract_upi_ids(text),
        "domains": [url_utils.domain_of(u) for u in urls if url_utils.domain_of(u)],
        "languages": ["tamil"] if text_utils.has_tamil(text) else ["english"],
    }
    return verdict


async def _none_provider() -> dict:
    return {"available": False, "reason": "no URL in message"}


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> dict:
    verdict = await _run_pipeline(request.text, request.url, request.language)
    log_event(
        logger, "analysis_completed",
        classification=verdict["classification"],
        risk=verdict["risk_score"],
        providers=",".join(k for k, v in verdict["sources"].items() if v),
    )
    return verdict


@router.post("/analyze/image", response_model=AnalyzeResponse)
async def analyze_image(image: UploadFile = File(...)) -> dict:
    from ..services import ocr_service

    if not (image.content_type or "").startswith("image/"):
        raise HTTPException(status_code=415, detail="Upload an image file (png/jpg/webp)")
    image_bytes = await image.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Empty upload")

    ocr = ocr_service.extract_text(image_bytes)
    if not ocr.get("available") or not ocr.get("text"):
        raise HTTPException(
            status_code=503,
            detail=ocr.get("reason", "OCR is unavailable — paste the message text instead"),
        )

    verdict = await _run_pipeline(ocr["text"])
    verdict["extracted"]["ocr_text"] = ocr["text"][:1000]
    log_event(logger, "image_analysis_completed", classification=verdict["classification"])
    return verdict

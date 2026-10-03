# OCR interface for screenshot input (spec section 18).
# Clean interface: extract_text(image_bytes) -> {"available": bool, "text": str}.
# Uses pytesseract only when a Tesseract binary is actually reachable;
# otherwise reports unavailable so the caller can degrade gracefully.
import os
import shutil

from ..utils.logging import get_logger, log_event

logger = get_logger("meyvizhi.ocr")


def _tesseract_binary() -> str | None:
    override = os.environ.get("TESSERACT_PATH")
    if override and os.path.isfile(override):
        return override
    found = shutil.which("tesseract")
    return found


def extract_text(image_bytes: bytes) -> dict:
    binary = _tesseract_binary()
    if not binary:
        return {"available": False, "text": "", "reason": "Tesseract OCR not installed on the server"}
    try:
        import io

        import pytesseract
        from PIL import Image

        image = Image.open(io.BytesIO(image_bytes))
        text = pytesseract.image_to_string(image, lang="eng+tam" if _has_lang("tam") else "eng")
        return {"available": True, "text": (text or "").strip()}
    except ImportError:
        return {"available": False, "text": "", "reason": "pytesseract/Pillow not installed"}
    except Exception as exc:  # noqa: BLE001
        log_event(logger, "ocr_error", error=type(exc).__name__)
        return {"available": False, "text": "", "reason": "OCR failed"}


def _has_lang(lang: str) -> bool:
    try:
        import pytesseract
        binary = _tesseract_binary()
        langs = pytesseract.get_languages(config="", path=os.path.dirname(binary)) if binary else []
        return lang in (langs or [])
    except Exception:
        return False

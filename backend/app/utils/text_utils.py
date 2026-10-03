# Text normalization and entity extraction helpers.
import re

PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?\b[6-9]\d{9}\b")
UPI_RE = re.compile(r"\b[a-zA-Z0-9._-]{2,}@(?:ok(?:hdfcbank|icici|axis|sbi|biz)|paytm|ybl|apl|upi|ibl|axl)\b")
WHITESPACE_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    return WHITESPACE_RE.sub(" ", (text or "").strip())


def lower(text: str) -> str:
    return (text or "").lower()


def extract_phones(text: str) -> list:
    phones = []
    for match in PHONE_RE.findall(text or ""):
        digits = re.sub(r"\D", "", match)
        if len(digits) > 10:
            digits = digits[-10:]
        if digits not in phones:
            phones.append(digits)
    return phones


def extract_upi_ids(text: str) -> list:
    seen, ids = set(), []
    for match in UPI_RE.findall(text or ""):
        if match.lower() not in seen:
            seen.add(match.lower())
            ids.append(match.lower())
    return ids


def has_tamil(text: str) -> bool:
    return any("\u0b80" <= ch <= "\u0bff" for ch in (text or ""))


TANGLISH_MARKERS = ["aagidum", "pannunga", "ungal", "irka", "irunga", "kudukka", "seinga", "aaga", "pannunga", "vanthu", "kitta"]

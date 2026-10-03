# Blocklist engine (hardcoded scam intelligence).
# Loads curated scam datasets from app/data/:
#   links.txt            — 10k+ known scam/phishing domains
#   malicious-terms.txt  — known phishing phrases (Discord Nitro, Steam, airdrop...)
#   trailing-slashes.txt — URL path patterns used by phishing pages (/claim, /airdrop...)
# scam-links.yml is intentionally not loaded — it duplicates links.txt in YAML form.
import os

from ..utils.url_utils import domain_of, path_of, registered_domain
from ..utils.logging import get_logger

logger = get_logger("meyvizhi.blocklist")

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

SCAM_DOMAINS: set = set()
MALICIOUS_TERMS: list = []
SUSPICIOUS_PATHS: list = []


def _load_lines(filename: str) -> list:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        logger.warning("blocklist file missing: %s", filename)
        return []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return [line.strip().lower() for line in fh if line.strip() and not line.strip().startswith("#")]


def _ensure_loaded() -> None:
    if SCAM_DOMAINS:
        return
    SCAM_DOMAINS.update(_load_lines("links.txt"))
    MALICIOUS_TERMS.extend(_load_lines("malicious-terms.txt"))
    SUSPICIOUS_PATHS.extend(_load_lines("trailing-slashes.txt"))


def check(text: str, urls: list) -> list:
    """Return heuristic signals for blocklisted content. A known scam domain is
    treated as near-certain (score 65 => SCAM on its own)."""
    _ensure_loaded()
    signals = []

    seen_domains = set()
    for url in urls[:5]:
        host = domain_of(url)
        reg = registered_domain(host)
        key = reg or host
        if not key or key in seen_domains:
            continue
        seen_domains.add(key)
        if key in SCAM_DOMAINS or host in SCAM_DOMAINS:
            signals.append({
                "name": "BLOCKLISTED_LINK", "score": 65,
                "detail": f"{key} is a known scam/phishing domain in MEYVIZHI's blocklist",
            })
        else:
            # Path check only for domains not already blocklisted
            path = path_of(url).lower().rstrip("/")
            for pattern in SUSPICIOUS_PATHS:
                if path == pattern or path.startswith(pattern):
                    signals.append({
                        "name": "SUSPICIOUS_PATH", "score": 12,
                        "detail": f"URL path {pattern} is common in phishing pages",
                    })
                    break

    t = (text or "").lower()
    term_hits = [term for term in MALICIOUS_TERMS if term in t]
    if term_hits:
        signals.append({
            "name": "MALICIOUS_TERM", "score": 12 + min(len(term_hits), 4) * 3,
            "detail": f"known phishing phrase: \"{term_hits[0]}\"",
        })

    return signals

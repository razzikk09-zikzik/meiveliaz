# URL extraction and reputation helpers.
import base64
import ipaddress
import re
from urllib.parse import urlparse

# Matches http(s) links, www links and bare domains with a plausible TLD.
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9-]*)+"
    r"\.(?:com|net|org|in|co|io|xyz|top|info|online|site|club|icu|link|live|shop|store|buzz|gov|edu|sbi)\b[^\s<>\"']*",
    re.IGNORECASE,
)

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
    "tiny.cc", "shorturl.at", "rebrand.ly", "ow.ly", "bit.do",
}

# TLDs that on their own are only a weak hint (never sufficient for SCAM alone).
RISKY_TLDS = {
    "xyz", "top", "club", "online", "site", "info", "buzz", "icu", "live",
    "shop", "store", "link", "cfd", "rest",
}

TRUSTED_TLDS = {"gov", "gov.in", "edu", "ac.in"}

# Brand -> official domains. A brand name appearing inside a domain that is
# NOT the official one is a strong impersonation signal.
BRAND_DOMAINS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi"},
    "state bank": {"sbi.co.in", "onlinesbi.sbi"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "pnb": {"pnbindia.in"},
    "rbi": {"rbi.org.in"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "bluedart": {"bluedart.com"},
    "delhivery": {"delhivery.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "tneb": {"tnebltd.gov.in"},
    "aadhaar": {"uidai.gov.in"},
    "income tax": {"incometax.gov.in"},
}


def extract_urls(text: str) -> list:
    if not text:
        return []
    seen, urls = set(), []
    for match in URL_RE.findall(text):
        url = match.strip(".,;:!?)]}'\"")
        key = url.lower()
        if key not in seen:
            seen.add(key)
            urls.append(url)
    return urls


def _ensure_scheme(url: str) -> str:
    return url if url.lower().startswith(("http://", "https://")) else f"http://{url}"


def domain_of(url: str) -> str:
    try:
        host = urlparse(_ensure_scheme(url)).netloc.lower()
        return host.split("@")[-1].split(":")[0]
    except Exception:
        return ""


def path_of(url: str) -> str:
    try:
        return urlparse(_ensure_scheme(url)).path or "/"
    except Exception:
        return "/"


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def subdomain_count(host: str) -> int:
    if not host:
        return 0
    # Registrable-domain heuristic: ignore common two-part public suffixes.
    parts = host.split(".")
    suffix_two_part = {"co.in", "gov.in", "ac.in", "org.in", "net.in", "com.au", "co.uk"}
    take = 2 if ".".join(parts[-2:]) in suffix_two_part else 1
    return max(0, len(parts) - take - 1)


def tld_of(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    two_part = ".".join(parts[-2:])
    if two_part in TRUSTED_TLDS or two_part in ("co.in", "gov.in", "ac.in", "org.in"):
        return two_part
    return parts[-1] if parts else ""


def registered_domain(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in ("co.in", "gov.in", "ac.in", "org.in", "net.in", "com.au", "co.uk"):
        return ".".join(parts[-3:]) if len(parts) >= 3 else host
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def brand_mismatch(url: str) -> tuple:
    """Return (brand_name, official_domain) when a brand is impersonated in a
    domain that is not official. Empty tuple when no mismatch."""
    host = domain_of(url)
    if not host:
        return ()
    reg = registered_domain(host)
    for brand, officials in BRAND_DOMAINS.items():
        token = brand.replace(" ", "")
        in_host = token in host.replace("-", "").replace(".", "")
        if not in_host:
            continue
        official_hit = any(
            reg == off or reg.endswith("." + off) or host == off for off in officials
        )
        if not official_hit:
            return (brand.title(), sorted(officials)[0])
    return ()


def virustotal_url_id(url: str) -> str:
    """VirusTotal v3 URL object id: unpadded base64url of the URL."""
    return base64.urlsafe_b64encode(_ensure_scheme(url).encode()).decode().rstrip("=")

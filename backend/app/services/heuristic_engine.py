# MEYVIZHI deterministic heuristic engine.
# Pure-Python scam detection signals (spec section 8). Signals are hints —
# a single signal (e.g. a risky TLD) must never alone classify as SCAM.
from typing import List

from ..utils import text_utils, url_utils

SIGNAL_URGENCY = "URGENCY"
SIGNAL_OTP = "OTP_REQUEST"
SIGNAL_PAYMENT = "PAYMENT_REQUEST"
SIGNAL_BANK = "BANK_IMPERSONATION"
SIGNAL_GOV = "GOV_IMPERSONATION"
SIGNAL_SUSPICIOUS_DOMAIN = "SUSPICIOUS_DOMAIN"
SIGNAL_BRAND_IN_DOMAIN = "BRAND_IN_DOMAIN"
SIGNAL_SHORTENER = "URL_SHORTENER"
SIGNAL_RAW_IP = "RAW_IP_ADDRESS"
SIGNAL_SUBDOMAINS = "EXCESSIVE_SUBDOMAINS"
SIGNAL_RISKY_TLD = "RISKY_TLD"
SIGNAL_MISLEADING_PATH = "MISLEADING_PATH"

URGENCY_WORDS = [
    "urgent", "immediately", "immediate action", "blocked", "suspend", "suspended",
    "deactivate", "expire", "expires", "expiry", "act now", "final warning",
    "last warning", "within 24", "24 hours", "tonight", "right now", "today only",
    "account freeze", "will be closed", "verify now", "few minutes",
    "account block", "account will be blocked", "block aagidum", "close aagidum",
]

VERIFICATION_PATH_WORDS = ["verify", "verification", "update", "secure", "login", "confirm", "unlock"]

OTP_WORDS = [
    "otp", "one time password", "one-time password", "upi pin", " pin", "cvv",
    "cvc", "password", "verification code", "card details", "bank details",
    "net banking password", "mpin", "atm pin",
]

PAYMENT_WORDS = [
    "pay", "payment", "transfer", "send money", "collect", "registration fee",
    "processing fee", "delivery fee", "customs fee", "refund", "advance",
    "deposit", "registration amount", "pay now", "rs.", "rs ", "rupees", "₹",
]

BANK_BRANDS = ["sbi", "hdfc", "icici", "axis bank", "kotak", "pnb", "state bank", "rbi"]
GOV_BRANDS = ["police", "cbi", "electricity department", "tneb", "aadhaar", "uidai",
              "income tax", "gst", "income tax department", "government"]

# Scam-story hooks that commonly precede payment/credential requests.
HOOK_WORDS = [
    "kyc", "kyc update", "prize", "lottery", "cashback", "winner", "congratulations",
    "claim", "work from home", "earn", "part time job", "electricity bill",
    "power cut", "parcel", "courier", "customs", "delivery", "gift", "recharge",
]


def _signal(name: str, score: int, detail: str) -> dict:
    return {"name": name, "score": min(score, 40), "detail": detail}


def analyze(text: str) -> dict:
    """Run deterministic heuristics on a message (and any URLs inside it).

    Returns {"score": 0-100, "signals": [{name, score, detail}]}.
    """
    raw = text or ""
    t = text_utils.lower(raw)
    signals: List[dict] = []

    urls = url_utils.extract_urls(raw)

    # --- Urgency pressure ---
    hits = [w for w in URGENCY_WORDS if w in t]
    if hits:
        signals.append(_signal(SIGNAL_URGENCY, 12 + min(len(hits), 4) * 3, f"pressure language: {hits[0]!r}"))

    # --- OTP / credential requests ---
    hits = [w for w in OTP_WORDS if w in t]
    if hits:
        signals.append(_signal(SIGNAL_OTP, 35, f"requests credential: {hits[0]!r}"))

    # --- Payment requests ---
    hits = [w for w in PAYMENT_WORDS if w in t]
    hook_hits = [w for w in HOOK_WORDS if w in t]
    if hits and (hook_hits or urls):
        signals.append(_signal(SIGNAL_PAYMENT, 16 + min(len(hits), 4) * 3, f"payment request in suspicious context: {hits[0]!r}"))
    elif hits:
        signals.append(_signal(SIGNAL_PAYMENT, 10, f"payment request: {hits[0]!r}"))

    # Classic scam story: prize/job/courier hook + money ask
    if hook_hits and hits:
        signals.append(_signal("SCAM_PATTERN", 10, f"scam story hook ({hook_hits[0]!r}) combined with a money request"))

    # --- Impersonation ---
    bank_hits = [b for b in BANK_BRANDS if b in t]
    if bank_hits:
        signals.append(_signal(SIGNAL_BANK, 18, f"claims to be {bank_hits[0]!r}"))
    gov_hits = [b for b in GOV_BRANDS if b in t]
    if gov_hits:
        signals.append(_signal(SIGNAL_GOV, 15, f"claims to be {gov_hits[0]!r}"))

    # --- Contact requests with personal numbers ---
    phones = text_utils.extract_phones(raw)
    if phones and ("call" in t or "whatsapp" in t):
        signals.append(_signal("CONTACT_REQUEST", 10, f"asks to call/WhatsApp an unverified number ({phones[0][:5]}xxxxx)"))

    # --- Scam-story hooks alone are weak ---
    if hook_hits and not hits:
        signals.append(_signal("COMMON_SCAM_HOOK", 6, f"common scam hook: {hook_hits[0]!r}"))

    # --- URL signals ---
    brand_flag, lure_flag = False, False
    for url in urls[:3]:
        host = url_utils.domain_of(url)
        if not host:
            continue
        if url_utils.is_ip_host(host):
            signals.append(_signal(SIGNAL_RAW_IP, 20, f"link uses a raw IP address: {host}"))
            continue
        # Verification lure in the URL path
        path = url_utils.path_of(url).lower()
        lure = [w for w in VERIFICATION_PATH_WORDS if w in path]
        if lure:
            lure_flag = True
            signals.append(_signal("VERIFICATION_REQUEST", 12, f"URL asks to {lure[0]!r} — classic phishing pattern"))
        if host in URL_SHORTENERS_SET:
            signals.append(_signal(SIGNAL_SHORTENER, 12, f"link hides the real destination ({host})"))
        tld = url_utils.tld_of(host)
        if tld in url_utils.RISKY_TLDS:
            signals.append(_signal(SIGNAL_RISKY_TLD, 10, f"domain uses .{tld} — common in phishing, weak signal alone"))
        subs = url_utils.subdomain_count(host)
        if subs >= 3:
            signals.append(_signal(SIGNAL_SUBDOMAINS, 14, f"domain has {subs} subdomain levels: {host}"))
        # Brand impersonation inside a non-official domain
        mismatch = url_utils.brand_mismatch(url)
        if mismatch:
            brand, official = mismatch
            brand_flag = True
            signals.append(_signal(SIGNAL_BRAND_IN_DOMAIN, 30, f"{brand} appears in a domain that is not official (official: {official})"))
        # Misleading path: brand name only in the path
        if any(b.replace(" ", "") in path for b in BANK_BRANDS) and not any(b.replace(" ", "") in host for b in BANK_BRANDS):
            signals.append(_signal(SIGNAL_MISLEADING_PATH, 8, "brand name only appears in the URL path, not the domain"))

    # Phishing combo: impersonated brand + verification lure in the URL
    if brand_flag and lure_flag:
        signals.append(_signal("PHISHING_PATTERN", 12, "impersonated brand combined with a verification link"))

    # --- Score: cap so one weak signal can never reach SCAM alone ---
    total = sum(s["score"] for s in signals)
    if len(signals) == 1:
        total = min(total, 45)  # a single signal can be at most SUSPICIOUS
    score = max(2, min(98, total))
    return {"available": True, "score": score, "signals": signals, "urls": urls}


URL_SHORTENERS_SET = url_utils.URL_SHORTENERS

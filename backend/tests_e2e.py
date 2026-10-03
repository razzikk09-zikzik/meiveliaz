"""MEYVIZHI end-to-end backend tests (spec sections 23 and 32).

Run with the backend up on localhost:8000:
    .venv\\Scripts\\python.exe tests_e2e.py
"""
import json

import httpx

BASE = "http://127.0.0.1:8000"
ok_count = 0
fail_count = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global ok_count, fail_count
    if condition:
        ok_count += 1
        print(f"  PASS  {name}")
    else:
        fail_count += 1
        print(f"  FAIL  {name}  {detail}")


ANALYZE_CASES = [
    # (label, text, expected classification, must-contain signal names)
    ("Demo Tanglish scam (spec 23)",
     "Sir ungal SBI account block aagidum. Inga click pannunga: https://sbi-kyc-update.xyz/verify",
     "SCAM", {"BANK_IMPERSONATION", "URGENCY", "BRAND_IN_DOMAIN", "VERIFICATION_REQUEST"}),
    ("Normal safe message",
     "Hi ma, reaching home at 7pm. Dont forget the doctor appointment tomorrow morning.",
     "SAFE", set()),
    ("Courier scam",
     "Your parcel is held at customs. Pay Rs.199 delivery fee at: http://dhl-india-delivery.net/pay to release.",
     "SCAM", {"PAYMENT_REQUEST", "BRAND_IN_DOMAIN"}),
    ("Fake job offer",
     "Hiring! Work from home. Earn Rs.50,000/month. No experience. Pay Rs.2000 registration fee. WhatsApp 9123456789",
     "SUSPICIOUS", {"PAYMENT_REQUEST"}),
    ("UPI prize scam",
     "Congratulations! You received Rs.5000 cashback. Click to claim: http://upi-prize.xyz/claim",
     "SUSPICIOUS", set()),
    ("Tanglish OTP scam",
     "Sir ungal OTP vaanga police station irundu call vandhurchi. OTP kudutha account block aagidum",
     "SCAM", {"OTP_REQUEST"}),
    ("URL only input",
     "https://sbi-kyc-update.xyz/verify",
     "SCAM", {"BRAND_IN_DOMAIN"}),
    ("Legit URL stays safe",
     "Read this article https://www.wikipedia.org/Chennai today",
     "SAFE", set()),
]


def main() -> None:
    print("== Health & config ==")
    r = httpx.get(f"{BASE}/health", timeout=10)
    check("GET /health = ok", r.status_code == 200 and r.json()["status"] == "ok")
    r = httpx.get(f"{BASE}/api/config-status", timeout=10)
    check("config-status reports providers", r.status_code == 200 and all(v in ("YES", "NO") for v in r.json().values()))
    print(f"        {r.json()}")

    print("== Analyze test matrix ==")
    for label, text, expected, must_signals in ANALYZE_CASES:
        r = httpx.post(f"{BASE}/api/analyze", json={"text": text}, timeout=15)
        check(f"POST /api/analyze 200 ({label})", r.status_code == 200, f"status={r.status_code}")
        if r.status_code != 200:
            continue
        data = r.json()
        got = data["classification"]
        names = {s["name"] for s in data["signals"]}
        check(f"  {label}: expected {expected}, got {got} ({data['risk_score']})", got == expected)
        if must_signals:
            missing = must_signals - names
            check(f"  {label}: signals include {sorted(must_signals)}", not missing, f"missing {missing}")

    print("== Validation ==")
    r = httpx.post(f"{BASE}/api/analyze", json={"text": ""}, timeout=10)
    check("empty input rejected 422", r.status_code == 422)
    r = httpx.post(f"{BASE}/api/analyze", json={"text": "x" * 6000}, timeout=10)
    check("oversized text rejected 422", r.status_code == 422)

    print("== Reports ==")
    r = httpx.post(f"{BASE}/api/reports", json={
        "scam_type": "SMS", "message": "Fake bank KYC message", "location": "Velachery",
        "money_lost": "no", "anonymous": True,
    }, timeout=15)
    check("POST /api/reports 201", r.status_code == 201, f"status={r.status_code} body={r.text[:200]}")
    check("report returns id", bool(r.json().get("id")))
    check("graceful persistence note", r.json().get("stored") in (True, False))
    r = httpx.post(f"{BASE}/api/reports", json={"scam_type": "SMS", "money_lost": "maybe"}, timeout=10)
    check("invalid money_lost rejected 422", r.status_code == 422)

    print("== Analyst auth (spec 12) ==")
    r = httpx.get(f"{BASE}/api/reports", timeout=10)
    check("unauthenticated /api/reports -> 401", r.status_code == 401, f"got {r.status_code}")
    r = httpx.get(f"{BASE}/api/reports", headers={"Authorization": "Bearer invalid-token"}, timeout=10)
    check("bad token -> 401 or 503", r.status_code in (401, 503), f"got {r.status_code}")
    r = httpx.post(f"{BASE}/api/auth/login", json={"email": "analyst@example.com", "password": "wrong"}, timeout=10)
    check("login without Supabase -> 503 graceful", r.status_code == 503, f"got {r.status_code}")

    print("== Threats ==")
    r = httpx.get(f"{BASE}/api/threats", timeout=10)
    data = r.json()
    check("GET /api/threats 200", r.status_code == 200)
    check("threats source marked", data.get("source") in ("seed", "supabase"))
    check("seed threats present", len(data.get("threats", [])) >= 3)
    check("seed alert present", len(data.get("alerts", [])) >= 1)

    print("== Rate limiting ==")
    got_429 = False
    for _ in range(45):
        rr = httpx.get(f"{BASE}/api/config-status", timeout=5)
        if rr.status_code == 429:
            got_429 = True
            break
    check("rate limiter returns 429 when hammered", got_429)

    print(f"\nRESULT: {ok_count} passed, {fail_count} failed")
    raise SystemExit(1 if fail_count else 0)


if __name__ == "__main__":
    main()

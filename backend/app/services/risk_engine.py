# MEYVIZHI Risk Engine — the central brain (spec section 13).
# Combines provider signals with prototype weights and renormalizes when a
# provider is unavailable. Scores are NOT probabilities.
from . import heuristic_engine

WEIGHTS = {
    "gemini": 0.30,
    "heuristics": 0.35,
    "virustotal": 0.20,
    "graph": 0.15,
}

THRESHOLDS = {"SAFE": (0, 30), "SUSPICIOUS": (31, 60), "SCAM": (61, 100)}

RECOMMENDATIONS = {
    "SAFE": [
        "Stay alert — scammers constantly change tactics.",
        "Never share OTP, PIN or CVV, even if a message looks harmless.",
    ],
    "SUSPICIOUS": [
        "Do not click any links or call the number in the message.",
        "Verify the message with the official company website or app.",
        "Never share OTP, PIN or CVV.",
        "Report it in MEYVIZHI to warn others.",
    ],
    "SCAM": [
        "Do not click any links or open attachments.",
        "Do not share OTP, PIN, CVV or any personal details.",
        "If you already paid or shared details, call 1930 immediately.",
        "Report this scam in MEYVIZHI and at cybercrime.gov.in.",
    ],
}


def _classify(score: int) -> str:
    if score >= 61:
        return "SCAM"
    if score >= 31:
        return "SUSPICIOUS"
    return "SAFE"


def combine(gemini: dict, heuristics: dict, virustotal: dict, graph: dict) -> dict:
    """Fuse provider signals into a final classification.

    Each provider dict has {"available": bool, "score": int|None, ...}.
    Weights are renormalized over the available providers. A provider that is
    available but has nothing meaningful to add (e.g. graph with zero related
    reports) may set "neutral": True and is excluded from weighting.
    """
    contributions = {}
    for name, provider in (("gemini", gemini), ("heuristics", heuristics),
                           ("virustotal", virustotal), ("graph", graph)):
        if provider.get("available") and not provider.get("neutral") and isinstance(provider.get("score"), (int, float)):
            contributions[name] = (WEIGHTS[name], provider["score"])

    if not contributions:
        # Fail safe: no provider signal at all — never auto-SCAM.
        score = max(2, min(30, int(heuristics.get("score") or 0)))
    else:
        weight_sum = sum(w for w, _ in contributions.values())
        score = round(sum(w * s for w, s in contributions.values()) / weight_sum)

    classification = _classify(score)

    # Merge heuristic + AI signals into one display list (strongest first).
    signals = []
    for s in (heuristics.get("signals") or []):
        signals.append({"name": s["name"], "score": s["score"], "detail": s.get("detail")})
    for s in (gemini.get("signals") or []):
        if isinstance(s, str):
            signals.append({"name": s.upper().replace(" ", "_"), "score": 0, "detail": "AI signal"})
        elif isinstance(s, dict):
            signals.append({"name": str(s.get("name", "AI_SIGNAL")), "score": int(s.get("score", 0) or 0), "detail": s.get("detail")})
    signals.sort(key=lambda s: -s["score"])

    explanation = _explain(classification, score, gemini, heuristics, virustotal, graph)
    return {
        "classification": classification,
        "risk_score": score,
        "signals": signals,
        "explanation": explanation,
        "recommendations": RECOMMENDATIONS[classification],
        "sources": {
            "gemini": bool(gemini.get("available")),
            "heuristics": True,
            "virustotal": bool(virustotal.get("available")),
            "graph": bool(graph.get("available")),
        },
    }


def _explain(classification, score, gemini, heuristics, virustotal, graph) -> str:
    parts = []
    if gemini.get("available") and gemini.get("explanation"):
        parts.append(gemini["explanation"])
    top = (heuristics.get("signals") or [])[:3]
    if top:
        names = ", ".join(s["name"].replace("_", " ").lower() for s in top)
        parts.append(f"Detected heuristic signals: {names}.")
    if virustotal.get("available"):
        parts.append(
            f"VirusTotal flags this URL with {virustotal.get('malicious', 0)} malicious "
            f"and {virustotal.get('suspicious', 0)} suspicious reports."
        )
    if graph.get("available") and graph.get("related_reports"):
        parts.append(
            f"Community graph links this message to {graph['related_reports']} other report(s) "
            f"through shared phone numbers, domains or UPI IDs."
        )
    if not parts:
        parts.append("No strong scam signals found in this message.")
    return " ".join(parts)[:600]

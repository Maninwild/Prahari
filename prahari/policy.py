"""Scores prioritize review; baseline ML is never block eligible."""

from .schemas import CATEGORIES

VERSION = "review-first-0.2"


def decide(findings, coverage, uncertain=False, demo_strict=False, review_threshold=30):
    scores = {c: None for c in CATEGORIES}
    for c in CATEGORIES:
        detector = "phishing" if c == "phishing" else "request_ml"
        if (
            coverage.get(detector) == "complete"
            or c != "phishing"
            and coverage.get("rules") == "complete"
        ):
            scores[c] = 0.0
    for finding in findings:
        scores[finding.category] = max(scores[finding.category] or 0, finding.score)
    values = [v for v in scores.values() if v is not None]
    risk = round(max(values), 2) if values else None
    reasons = []
    degraded = any(v in ("error", "partial") for v in coverage.values())
    # Explicit local demo profile only. Never a claim of validated production blocking.
    if (
        demo_strict
        and not degraded
        and any(
            f.evidence_kind == "rule" and f.rule_id in ("PRH-004", "PRH-006", "PRH-011")
            for f in findings
        )
    ):
        return (
            "Block",
            risk,
            scores,
            [
                "Strict demonstration policy matched an enabled rule. No traffic was intercepted."
            ],
        )
    if degraded:
        reasons.append("Required analysis is incomplete.")
    if coverage.get("phishing") == "complete":
        reasons.append(
            "Legacy phishing model is experimental; URL scans require review until retraining."
        )
    if uncertain:
        reasons.append("Request model prediction is weak or ambiguous.")
    if risk is not None and risk >= review_threshold:
        reasons.append("Threat indicators exceed the provisional review threshold.")
    if reasons or risk is None:
        return "Review", risk, scores, reasons or ["No supported analysis completed."]
    return (
        "Allow",
        risk,
        scores,
        [
            "No supported detector exceeded the provisional review threshold; this is not proof of safety."
        ],
    )

"""Scores prioritize review; baseline ML is never block eligible."""
from .schemas import CATEGORIES
VERSION = 'hybrid-1.0'


def decide(findings, coverage, uncertain=False, demo_strict=False):
    scores = {c: None for c in CATEGORIES}
    for c in CATEGORIES:
        detector = 'phishing' if c == 'phishing' else 'request_ml'
        if coverage.get(detector) == 'complete' or c != 'phishing' and coverage.get('rules') == 'complete': scores[c] = 0.0
    for finding in findings:
        scores[finding.category] = max(scores[finding.category] or 0, finding.score)
    values = [v for v in scores.values() if v is not None]
    risk = round(max(values), 2) if values else None
    reasons = []
    degraded = any(v in ('error', 'partial') for v in coverage.values())
    # Explicit local demo profile only. Never a claim of validated production blocking.
    if demo_strict and any(f.evidence_kind == 'rule' and f.rule_id in ('PRH-002', 'PRH-004', 'PRH-006', 'PRH-009', 'PRH-010', 'PRH-011') for f in findings):
        return 'Block', risk, scores, ['Protection policy matched a blocking rule. Enforcement depends on the connected application.']
    if degraded: reasons.append('Required analysis is incomplete.')
    if uncertain: reasons.append('Request model prediction is weak or ambiguous.')
    if risk is not None and risk >= 30: reasons.append('Threat indicators exceed the provisional review threshold.')
    if reasons or risk is None:
        return 'Review', risk, scores, reasons or ['No supported analysis completed.']
    return 'Allow', risk, scores, ['No supported detector exceeded the provisional review threshold; this is not proof of safety.']

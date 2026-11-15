from datetime import datetime, timezone
import time
import uuid
from .schemas import ScanResult, Finding
from .parsing import parse, views
from .detectors.rules import inspect, LABELS, RULESET_VERSION
from .policy import decide, VERSION

class Engine:
    def __init__(self, models, demo_strict=False):
        self.models = models
        self.demo_strict = demo_strict

    def scan(self, data):
        start = time.perf_counter()
        parsed = parse(data)
        findings, signals = [], {}
        coverage = {'parser': 'partial' if parsed.issues else 'complete', 'rules':'complete', 'request_ml':'complete', 'phishing':'not_applicable'}
        uncertain = False
        try:
            findings.extend(inspect(parsed.components))
            # Use the same component representation at training and inference.
            ml_text = '\n'.join(list(views(c))[-1][1] for c in parsed.components)
        except (UnicodeError, ValueError):
            coverage['rules'] = 'error'
            ml_text = ''
        if data.input_type == 'url' or not ml_text.strip():
            coverage['request_ml'] = 'not_applicable' if data.input_type == 'url' else 'partial'
        else:
            try:
                probabilities = self.models.request(ml_text)
                ranking = sorted(probabilities, key=probabilities.get, reverse=True)
                uncertain = probabilities[ranking[0]] < .55 or probabilities[ranking[0]] - probabilities[ranking[1]] < .12
                signals['request'] = {'probabilities':probabilities, 'calibrated':False, 'training':'100 synthetic examples', 'leading_class':ranking[0]}
                for label, category in LABELS.items():
                    findings.append(Finding(detector='request_ml', category=category, evidence_kind='model', summary='Uncalibrated request model score', score=100*probabilities[label], component='supported_components'))
            except Exception:
                coverage['request_ml'] = 'error'
        if parsed.url:
            try:
                probability = self.models.phishing(parsed.url)
                coverage['phishing'] = 'complete'
                signals['phishing'] = {'probability':probability, 'calibrated':True, 'experimental':True, 'note':'V2 domain-separated fit; calibration uses source plus synthetic variants. Not live reputation.'}
                findings.append(Finding(detector='phishing', category='phishing', evidence_kind='model', summary='Calibrated URL model score (source-domain evaluation)', score=100*probability, component='url'))
            except Exception:
                coverage['phishing'] = 'error'
        decision, risk, scores, reasons = decide(findings, coverage, uncertain, self.demo_strict)
        return ScanResult(scan_id=uuid.uuid4().hex, created_at=datetime.now(timezone.utc).isoformat(), status='partial' if any(v in ('error','partial') for v in coverage.values()) else 'complete', decision=decision, risk_score=risk, category_scores=scores, findings=findings, coverage=coverage, reasons=parsed.issues+reasons, model_signals=signals, versions={**self.models.versions, 'rules':RULESET_VERSION, 'policy':VERSION+('-demo-strict' if self.demo_strict else '')}, analysis_ms=round((time.perf_counter()-start)*1000,2))

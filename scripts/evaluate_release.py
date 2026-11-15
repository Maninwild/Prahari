import json,time,statistics,platform
from pathlib import Path
from prahari.engine import Engine
from prahari.detectors.models import Models
from prahari.schemas import ScanInput
from prahari.detectors.rules import LABELS
ROOT=Path(__file__).resolve().parents[1]
def main():
 cases=json.loads((ROOT/'evaluation/request_cases.json').read_text());engine=Engine(Models(),True);rows=[]
 for c in cases:
  r=engine.scan(ScanInput(input_type='payload',content=c['text']))
  rules={f.category for f in r.findings if f.evidence_kind=='rule'}
  ml=r.model_signals.get('request',{}).get('leading_class','Unavailable')
  rows.append({**c,'ml_prediction':ml,'rule_categories':sorted(rules),'hybrid_decision':r.decision,'analysis_ms':r.analysis_ms})
 attacks=[x for x in rows if x['label']!='Normal'];benign=[x for x in rows if x['label']=='Normal']
 out={'scope':'26 authored diagnostic cases, not an independent real-traffic benchmark. Includes known and template-similar regressions; labels express intended context.','python':platform.python_version(),'rows':rows,'summary':{'cases':len(rows),'benign':len(benign),'attack':len(attacks),'ml_correct_class':sum(x['ml_prediction']==x['label'] for x in rows),'rules_attack_family_hits':sum(LABELS[x['label']] in x['rule_categories'] for x in attacks),'rules_benign_flags':sum(bool(x['rule_categories']) for x in benign),'hybrid_attacks_not_allowed':sum(x['hybrid_decision']!='Allow' for x in attacks),'hybrid_benign_blocks':sum(x['hybrid_decision']=='Block' for x in benign),'hybrid_benign_reviews':sum(x['hybrid_decision']=='Review' for x in benign),'median_analysis_ms':statistics.median(x['analysis_ms'] for x in rows)}}
 (ROOT/'evaluation/request_diagnostics.json').write_text(json.dumps(out,indent=2));print(json.dumps(out['summary'],indent=2))
if __name__=='__main__':main()

"""Versioned Isolation Forest baseline; advisory only, never trains on live traffic."""
import hashlib,json
from pathlib import Path
import numpy as np
import joblib
from .detection import FEATURES

class AnomalyModel:
    def __init__(self):
        self.bundle=None;self.error=None
        root=Path(__file__).resolve().parents[2]/'models'
        try:
            metadata=json.loads((root/'behaviour_manifest.json').read_text())
            artifact=root/'behaviour.pkl'
            if hashlib.sha256(artifact.read_bytes()).hexdigest()!=metadata['sha256']:
                raise ValueError('Behaviour model integrity mismatch')
            self.bundle=joblib.load(artifact)
            self.metadata=metadata
        except Exception as exc:self.error=type(exc).__name__

    def status(self):
        return {'loaded':self.bundle is not None,'error':self.error,
          'scope':getattr(self,'metadata',{}).get('scope','unavailable'),
          'version':getattr(self,'metadata',{}).get('version','unavailable')}

    def analyse(self, f,kind):
        if self.bundle is None or f['count']<5:return None
        b=self.bundle[kind]
        x=np.log1p([[f[k] for k in FEATURES[kind]]])
        rarity=float(-b['model'].score_samples(x)[0])
        cutoff=b['cutoff']
        if rarity<=cutoff:return None
        deviations=sorted(((abs(float(x[0,i])-b['median'][i])/max(b['iqr'][i],.1),k)
           for i,k in enumerate(FEATURES[kind])),reverse=True)[:3]
        return {'id':'anomaly-'+kind,'title':'Unusual '+kind+' activity relative to the baseline',
          'kind':'model','score':round(min(90,60+100*(rarity-cutoff)),2),
          'raw_anomaly':round(rarity,5),'threshold':round(cutoff,5),
          'scope':self.metadata['scope'],'version':self.metadata['version'],
          'deviations':[{'feature':k,'observed':f[k]} for _,k in deviations],
          'explanation':'Largest baseline deviations; these are descriptive, not causal attributions.',
          'window_seconds':300}

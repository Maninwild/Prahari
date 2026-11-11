"""Reproducible synthetic baseline for exercising the anomaly pipeline, not a benchmark."""
import hashlib,json
from pathlib import Path
import joblib,numpy as np
from sklearn.ensemble import IsolationForest
from prahari.telemetry.detection import FEATURES

def main():
    rng=np.random.default_rng(20261005);bundle={};stats={}
    for kind in FEATURES:
        rows=[]
        for _ in range(1600):
            count=int(rng.poisson(12))+5
            if kind=='http':
                row=[count,min(count,int(rng.poisson(2))+1),int(rng.choice([0,0,0,1,2])),float(rng.beta(1,20)),0,int(rng.lognormal(9,.6))]
            else:
                out=int(rng.lognormal(11,1))
                row=[count,min(count,int(rng.poisson(2))+1),int(rng.poisson(1))+1,float(rng.beta(1,30)),out,float(rng.lognormal(-.5,.4))]
            rows.append(row)
        x=np.log1p(rows);train,validation=x[:1200],x[1200:]
        model=IsolationForest(n_estimators=100,random_state=42,n_jobs=1).fit(train)
        cutoff=float(np.quantile(-model.score_samples(validation),.99))
        bundle[kind]={'model':model,'cutoff':cutoff,'median':np.median(train,axis=0),
          'iqr':np.quantile(train,.75,axis=0)-np.quantile(train,.25,axis=0)}
        stats[kind]={'training_windows':1200,'calibration_windows':400,'cutoff':cutoff}
    root=Path(__file__).resolve().parents[1]/'models';root.mkdir(exist_ok=True)
    joblib.dump(bundle,root/'behaviour.pkl',compress=3)
    metadata={'version':'behaviour-synthetic-0.1','scope':'synthetic demonstration baseline; not production validated',
      'algorithm':'IsolationForest','seed':20261005,'features':FEATURES,'calibration':stats,
      'sha256':hashlib.sha256((root/'behaviour.pkl').read_bytes()).hexdigest()}
    (root/'behaviour_manifest.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps(metadata,indent=2))
if __name__=='__main__':main()

"""Reproducible v2 retrain. Augmentation is synthetic and never crosses domains."""
import argparse,json,hashlib,random,time
from pathlib import Path
from urllib.parse import urlsplit
import pandas as pd,numpy as np,joblib
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,confusion_matrix,brier_score_loss
from prahari.detectors.phishing_features import extract_features,FEATURE_NAMES,domain_group
ROOT=Path(__file__).resolve().parents[1]
PATHS=['/about','/login','/account/settings','/search?q=wireless+mouse','/docs/guide','/products/123?category=books','/support/reset-password','/blog/2026/09/news','/user/profile','/api/items?page=2']
def augment(df):
    rng=random.Random(41);rows=[]
    for row in df.itertuples():
        if row.y==0:
            p=urlsplit(row.URL);host=p.hostname or ''
            host=host[4:] if host.startswith('www.') else host
            rows.append({'URL':p.scheme+'://'+host+rng.choice(PATHS),'y':0,'group':row.group})
    return pd.concat([df,pd.DataFrame(rows)],ignore_index=True)
def matrix(df):return pd.DataFrame([extract_features(u) for u in df.URL],columns=FEATURE_NAMES)
def metrics(model,df):
    p=model.predict_proba(matrix(df))[:,1];y=df.y;pred=p>=.5
    return {'rows':len(df),'accuracy':accuracy_score(y,pred),'precision':precision_score(y,pred,zero_division=0),'recall':recall_score(y,pred,zero_division=0),'f1':f1_score(y,pred,zero_division=0),'brier':brier_score_loss(y,p),'confusion_matrix':confusion_matrix(y,pred).tolist()}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--dataset',required=True);args=parser.parse_args()
    source=Path(args.dataset);df=pd.read_csv(source,usecols=['URL','label']).dropna().drop_duplicates('URL');df['y']=1-df.label;df=df.drop(columns='label')
    def group(u):
        try:return domain_group(u)
        except ValueError:return None
    df['group']=df.URL.map(group);df=df.dropna();df=df[df.group!='']
    trainidx,restidx=next(GroupShuffleSplit(test_size=.3,random_state=42).split(df,groups=df.group));train=df.iloc[trainidx];rest=df.iloc[restidx]
    valididx,testidx=next(GroupShuffleSplit(test_size=.5,random_state=43).split(rest,groups=rest.group));valid=rest.iloc[valididx];test=rest.iloc[testidx]
    assert not set(train.group)&set(test.group) and not set(train.group)&set(valid.group) and not set(valid.group)&set(test.group)
    fullcounts={'train':len(train),'validation':len(valid),'test':len(test)}
    train=pd.concat([g.sample(min(20000,len(g)),random_state=42) for _,g in train.groupby('y')]);valid=pd.concat([g.sample(min(3000,len(g)),random_state=42) for _,g in valid.groupby('y')]);test=pd.concat([g.sample(min(4000,len(g)),random_state=42) for _,g in test.groupby('y')])
    train_aug=augment(train);valid_aug=augment(valid)
    print('Training',len(train_aug),'rows',flush=True)
    model=RandomForestClassifier(n_estimators=120,max_depth=16,min_samples_leaf=3,class_weight='balanced',n_jobs=2,random_state=42)
    model.fit(matrix(train_aug),train_aug.y)
    calibrated=CalibratedClassifierCV(FrozenEstimator(model),method='sigmoid');calibrated.fit(matrix(valid_aug),valid_aug.y)
    result={'dataset_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'source':'PhiUSIIL UCI 967; supplied CSV','split':'registered domain groups; 70/15/15; seed 42/43; sampled per class after split','full_split_rows':fullcounts,'training_original_rows':len(train),'training_synthetic_rows':len(train_aug)-len(train),'calibration_original_rows':len(valid),'calibration_synthetic_rows':len(valid_aug)-len(valid),'features':FEATURE_NAMES,'heldout_original':metrics(calibrated,test),'heldout_with_synthetic_benign_variants':metrics(calibrated,augment(test)),'limitations':['Single source dataset; no independent real-world validation','Generated benign subpaths are assumed benign, not verified pages','Probabilities calibrated on source-plus-synthetic validation, not deployment traffic']}
    path=ROOT/'models/phishing_v2.pkl';joblib.dump(calibrated,path)
    manifest=json.loads((ROOT/'models/manifest.json').read_text());manifest['phishing']={'file':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'version':'phishing-v2-domain-split','calibrated':True,'block_eligible':False,'feature_schema':'v2'}
    (ROOT/'models/manifest.json').write_text(json.dumps(manifest,indent=2));(ROOT/'evaluation/phishing_training.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2),flush=True)
if __name__=='__main__':main()

"""Build the illustrative request baseline offline. Not an evaluation benchmark."""
from pathlib import Path
import hashlib
import json
import re
import importlib.metadata
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from scripts.training_data import TRAINING_DATA
from prahari.parsing import parse, views
from prahari.schemas import ScanInput

ROOT = Path(__file__).resolve().parents[1]

def training_view(text):
    # Original classroom rows are shorthand, not consistently valid HTTP messages.
    # Convert shorthand once for this fixture-only training set.
    match = re.match(r'^[A-Z]+ (.*?)(?: HTTP/1\.[01])?$', text)
    text = match.group(1) if match else text
    if '?' in text:
        path, body = text.split('?',1)
        content = body
        kind = 'application/x-www-form-urlencoded'
    elif ' ' in text and '=' in text:
        _, content = text.split(' ',1)
        kind = 'application/x-www-form-urlencoded'
    else:
        content, kind = text, 'text/plain'
    parsed = parse(ScanInput(input_type='payload', content=content, content_type=kind))
    return '\n'.join(list(views(c))[-1][1] for c in parsed.components)


def main():
    texts, labels = [], []
    for label, samples in TRAINING_DATA.items():
        texts.extend(training_view(s) for s in samples)
        labels.extend([label]*len(samples))
    model = Pipeline([('tfidf', TfidfVectorizer(analyzer='char_wb', ngram_range=(2,5), sublinear_tf=True, max_features=18000)), ('model', LogisticRegression(C=4, max_iter=1500, class_weight='balanced', random_state=42))])
    model.fit(texts, labels)
    directory = ROOT / 'models'
    directory.mkdir(exist_ok=True)
    joblib.dump(model, directory / 'request_baseline.pkl')
    manifest_path=directory / 'manifest.json'
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    for name, file in [('request','request_baseline.pkl')]:
        manifest[name] = {'file':file, 'sha256':hashlib.sha256((directory/file).read_bytes()).hexdigest(), 'version':name+'-experimental-0.1', 'calibrated':False, 'block_eligible':False}
    manifest['environment'] = {n:importlib.metadata.version(n) for n in ['scikit-learn','numpy','pandas','joblib']}
    manifest['request_training_rows'] = len(texts)
    manifest['training_source_sha256'] = hashlib.sha256((ROOT/'scripts/training_data.py').read_bytes()).hexdigest()
    (directory/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print('Built experimental request baseline from',len(texts),'synthetic examples.')

if __name__ == '__main__': main()

from pathlib import Path
import hashlib
import json
import joblib
import pandas as pd
from .phishing_features import extract_features, FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[2]

class Models:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else ROOT / 'models'
        self.loaded = {}
        self.errors = {}
        self.versions = {}
        try:
            manifest = json.loads((self.directory / 'manifest.json').read_text())
        except (OSError, ValueError):
            manifest = {}
        for name in ['phishing', 'request']:
            try:
                item = manifest[name]
                path = self.directory / item['file']
                if path.parent.resolve() != self.directory.resolve(): raise ValueError('Artifact path')
                if hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']: raise ValueError('Artifact hash')
                model = joblib.load(path)
                if name=='phishing' and (item.get('feature_schema')!='v2' or model.n_features_in_!=len(FEATURE_NAMES)):raise ValueError('Feature schema mismatch')
                self.loaded[name] = model
                self.versions[name] = item['version']
            except Exception:
                self.errors[name] = 'Model unavailable or artifact integrity check failed.'

    def phishing(self, url):
        # v2 weights and v2 feature schema are bundled together.
        model = self.loaded['phishing']
        row = pd.DataFrame([extract_features(url)], columns=FEATURE_NAMES)
        index = list(model.classes_).index(1)
        return float(model.predict_proba(row)[0][index])

    def request(self, text):
        model = self.loaded['request']
        probabilities = dict(zip(map(str, model.classes_), map(float, model.predict_proba([text])[0])))
        return probabilities

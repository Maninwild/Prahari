# Model provenance and limitations

Both models were recovered from the user's existing `Prahari_Milestone_3.zip`. They were loaded and reserialized with joblib compression for the initial GitHub codebase. This did not retrain or replace their learned parameters. The manifest records the recovered artifact hashes, current hashes, versions, environment, and synthetic request training source hash.

| Detector | Implementation | Training evidence available here | Limit |
| --- | --- | --- | --- |
| Request | Character n-gram TF-IDF + multiclass logistic regression | 100 labeled synthetic examples and offline training script | No independent test set or accuracy claim |
| Phishing | Random forest over 22 legacy lexical URL features | Recovered weights and original feature extraction code | Original training data/pipeline unavailable; known hostname and shortener feature shortcomings |

Phishing inference retains the legacy feature schema to avoid changing feature meaning without retraining. Every successful URL scan requires review. URL structure rules supplement explainability but do not repair model bias. Request probabilities and phishing scores are uncalibrated model outputs. The unified risk index is a policy prioritization score. No ML model is eligible for autonomous blocking.

Only independently trusted artifacts should be loaded. Hash verification protects against accidental corruption relative to the manifest; it does not authenticate a publisher. Preserve Python 3.12 and pinned scikit-learn/numpy/pandas/joblib compatibility when using the packaged models.

Rebuilding the request fixture updates its current hash and environment metadata and preserves the independent phishing artifact's metadata. Any production replacement needs representative data, leakage-safe splits, independent evaluation, calibration, and threshold validation before promotion.

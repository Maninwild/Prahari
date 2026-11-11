# Evaluation and limits

## Phishing v2

Source: supplied PhiUSIIL CSV. SHA-256 and split configuration are recorded in evaluation/phishing_training.json. Registered domains, including private suffixes, are kept disjoint between training, calibration and test partitions. The random split seeds are 42 and 43. Sampling by class occurs only after splitting.

Training: 40,000 real labelled URLs plus 20,000 generated benign path variants. Calibration: 6,000 original URLs plus 3,000 generated benign variants from separate domains. Random Forest: 120 trees, depth 16, min leaf 3, balanced class weights. Sigmoid calibration is fit to the held-out calibration partition.

| Metric | Original test sample |
|---|---:|
| Rows | 8,000 |
| Accuracy | 98.625% |
| Precision (phishing) | 99.668% |
| Recall (phishing) | 97.575% |
| F1 (phishing) | 98.610% |
| True negative / false positive | 3,987 / 13 |
| False negative / true positive | 97 / 3,903 |

The additional synthetic-variant test is reported separately in JSON, not merged into the real-only headline. Generated paths are assumed benign rather than verified pages. All test data originates in the same underlying source; no deployment traffic, independent threat feed or temporal holdout was available. Calibration is source-specific. Do not claim guaranteed 98.6% accuracy on arbitrary internet URLs or zero-day attacks.

The known legitimate probes github.com, github.com/openai, Google's search URL and Microsoft's subpage now receive Allow. These are regression checks, not a representative benchmark.

## Request diagnostics

26 authored cases: 10 intended benign and 16 attack strings. Some resemble training examples; several benign examples deliberately contain code or relative paths. Their labels express author-supplied context that a generic text classifier does not know.

| Diagnostic | Count |
|---|---:|
| Correct ML top class | 23 / 26 |
| Rule family hits on attack cases | 16 / 16 |
| Rule flags on benign cases | 3 / 10 |
| Hybrid attack cases denied or reviewed | 16 / 16 |
| Benign cases blocked in Protect mode | 2 / 10 |
| Benign cases reviewed in Protect mode | 5 / 10 |

These are diagnostic counts, not representative accuracy. Rules already matched every attack in this small set, so this evidence does not establish added recall from ML. ML supplies an additional learned signal and uncertainty; larger independent evaluation is needed to establish its benefit and false-positive tradeoff.

Protect can block code discussion containing script markup or legitimate relative paths. Review-first is the conservative scan policy; the integration's monitor mode allows workload observation. Review annotations do not automatically exempt future requests.

## Functional verification

18 backend tests cover feature repairs, original detector cases, malformed input, encoding, duplicate fields, privacy, auth/origin checks, persisted policy/review, history and acknowledgement deduplication. Live Python/Node checks exercise HTTP 200/403/409/503 and show that denied requests do not increment the handler count. Chromium checks cover real UI interactions, export, review, mobile overflow and protected-board behavior. No Windows execution or Docker runtime verification is claimed.

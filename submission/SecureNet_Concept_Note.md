# Prahari: Explainable intrusion detection through session and network behaviour

## Problem

Individual web-request alerts provide limited context. Repeated login failures, slow probing and connections across many network ports can span several events. Small application teams need an understandable way to connect these signals and investigate the activity behind them.

## Proposed solution

Prahari combines URL and request analysis with session metadata and network-flow observations. A shared ingestion pipeline groups events into short behavioural windows, combines explicit rules with machine-learning signals, and presents correlated incidents with an evidence timeline. Analysts can investigate, resolve or label incidents as false positives. Existing application integrations enforce explicit request-level protection policies.

## Challenge alignment

The project targets AI-based real-time intrusion detection using session and network behavioural analysis. The present prototype includes application telemetry and a Zeek JSON connection-log adapter. Operational deployment and model validation are proposed work, rather than established outcomes.

## Technical approach

The FastAPI backend supplies authenticated ingestion, the original hybrid web detector and a SQLite incident store. A Node application integration emits pseudonymous session metadata. A Zeek adapter imports historical flows or follows a live log. Five-minute windows produce request counts, login-failure counts, error ratios, route diversity, network destination/port diversity and byte-volume features. Isolation Forest models supply experimental anomaly signals alongside explicit behavioural rules. A unified browser workspace shows the resulting risk index, evidence and incident state.

Application sessions and flow observations share an HMAC actor identity where sensor visibility permits. Replay streams are isolated and labelled. Input bodies, cookies and raw source IPs are excluded from telemetry; destination metadata remains access-controlled. Behavioural alerts recommend review. Automated actions are restricted to the existing explicit request-protection policy.

## Current implementation

The prototype runs locally and includes session tracking, seven behavioural rules, synthetic demonstration anomaly models, scan-to-incident linkage, persistent incidents, triage and export. Automated regression tests and a browser-driven demo verify the data flow. Network replay is demonstrated using authored Zeek-format examples. This does not establish performance on real network attacks.

## Development and validation plan

1. Confirm challenge rules, eligibility, concept-note format and whether existing code may be reused. Disclose the original phishing and web-attack work and the new contributions.
2. Deploy a lab sensor and generate consented normal application traffic, login-abuse scenarios, route probing and network scans. Record capture conditions and ground truth.
3. Train and evaluate on capture-separated, time-separated windows. Keep test captures untouched and compare rules-only, ML-only and hybrid detection.
4. Measure false alerts per hour, precision, recall, time to detection and processing latency. Evaluate shared IPs, benign bursts, backups and lost sensor events.
5. Improve incident prioritization and adapt thresholds using the validation set. Document limitations and prepare a reproducible live demonstration.

## Intended value and differentiation

The product connects a suspicious request to activity before and after it, with evidence that can be reviewed and exported. Its intended users are small application teams and teaching/security labs that need one workflow for understanding both web attacks and surrounding behaviour. Whether the hybrid model adds value above rules is an evaluation question, not a claimed result.

## Team and provenance

Manjunath Padgetwar and collaborator (name to be completed). Prahari builds on the team's earlier phishing and web-attack projects. Dataset provenance and existing model evaluation are documented in NOTICE.md and docs/EVALUATION.md. New behavioural models currently use generated demonstration data.

This is a draft concept note, not a registration or submitted entry. Confirm the organizer's current template and rules before submission.

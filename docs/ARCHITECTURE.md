# Architecture

Prahari is a modular monolith: the same Python analysis core serves the browser workspace and Node adapter. Static frontend assets are served by FastAPI; there is no parallel legacy interface.

Input validation → component parsing → applicable ML and rule detectors → category scores → policy decision → persisted redacted result. The adapter consults that result before the application handler and reports what actually happened.

| Module | Responsibility |
|---|---|
| schemas.py | Input, findings, decision, review and acknowledgement contracts |
| parsing.py | HTTP/query/form/JSON components and bounded inspection views |
| detectors/phishing_features.py | Corrected URL features and public-suffix grouping |
| detectors/models.py | Integrity-checked model loading and prediction |
| detectors/rules.py | Multi-category patterns, offsets and ephemeral excerpts |
| policy.py | Review-first and Protect decisions, separate from enforcement |
| engine.py | Unified analysis and coverage reporting |
| storage.py | SQLite scans, reviews, policy and acknowledgements |
| security.py | Optional bearer auth, origin controls and scan rate limiting |
| demo-app/prahari-client.mjs | Reusable integration client and persistent event outbox |
| demo-app/server.mjs | Protected community-board example |

URL scans run phishing ML and attack rules over URL components; request ML is not applied to arbitrary URL paths. HTTP/payload scans run request ML plus rules. An incoming Host header is never treated as a phishing destination. Submit an explicit URL scan for a link field. Request ML remains single-class, but rule findings preserve multiple families.

Input support is deliberately bounded: 10,000 characters, 64 KiB API bodies, at most 100 form/query parameters, bounded JSON depth and two heuristic decode passes. Invalid or unsupported inputs are rejected or marked incomplete; they do not silently become safe. Request parsing does not simulate every server and does not support file uploads, compressed bodies or chunked transfer semantics.

SQLite migrations are additive CREATE TABLE IF NOT EXISTS operations; previous milestone history remains readable. One local process/instance is the intended deployment. Multiple tenants, distributed policy rollout and durable exactly-once business transactions are outside this release.

## Version 2 telemetry pipeline

See [SECURENET_UPGRADE.md](SECURENET_UPGRADE.md) for the shared session/flow contract, rolling aggregation, Isolation Forest model scope, incident correlation and operational limits. The new modules live under `prahari/telemetry/`; adapters are `demo-app/telemetry.mjs` and `scripts/import_zeek.py`. These feed the existing workspace and retain links to original scan evidence.

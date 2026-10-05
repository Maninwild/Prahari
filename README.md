# Prahari

A working local threat workspace that combines phishing and web-attack analysis through one ingestion pipeline, one risk policy, one scan record, and one dashboard.

**Python 3.12 · FastAPI · scikit-learn · SQLite · JavaScript**

## Start

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m prahari
```

Open **http://127.0.0.1:8000/**. API documentation: **http://127.0.0.1:8000/docs**.
Use `python -m prahari --port 8001` if needed. Run commands from the repository root.

On Windows, double-click `run_windows.bat`, or use PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m prahari
```

## Included

- One composer for URLs, raw HTTP requests, and plain text / JSON / form payloads.
- Phishing classifier plus explainable URL structure rules.
- Request classifier plus SQL injection, XSS, command injection, and path traversal rules.
- Combined category scores and one Allow / Review / Block recommendation.
- Rule locations, decoding transformations, ML scores, coverage, versions, and decision reasons.
- SQLite scan history with detail reopening, decision filters, and pagination.
- Dashboard decision counts, category indicators, seven-day trends, incomplete analyses, and acknowledged enforcement counts.
- JSON export and documented REST endpoints.
- Optional Node protection adapter demonstrating handler isolation and authenticated acknowledgements.
- Hash-checked bundled models, reproducible request training, regression tests, and CI.

The frontend is served by FastAPI and needs no separate build or npm installation. Both entry points are `prahari/api.py` and `prahari/static/index.html`; the shared orchestrator is `prahari/engine.py`.

## Try the unified API

```bash
curl http://127.0.0.1:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"input_type":"http_request","content":"GET /products?page=2 HTTP/1.1"}'
```

The dashboard has examples for all five threat categories. A URL scan checks its URL structure with the phishing model and also inspects its path/query for web attacks. Full HTTP inputs require `METHOD /path HTTP/1.1`, one header per line, and a blank line before the body. The Host header is not treated as a phishing destination.

## Decisions and risk

Risk is the maximum applicable finding score across categories, on a 0–100 experimental policy index. It is **not a calibrated maliciousness probability**. ML and rules are displayed separately so the decision is explainable.

The default `review-first` policy permits low-scoring supported requests and recommends review when a model is uncertain, a detector is unavailable, an input is unsupported, or the configured risk threshold is reached. The recovered phishing model has known URL-shape limitations, so every URL scan requires Review pending retraining and independent evaluation.

`PRAHARI_POLICY=demo-strict` additionally recommends Block for selected destructive SQL, script-tag, and traversal rules when analysis is complete. ML alone cannot authorize Block. A recommendation does not intercept traffic.

## Protected application demo

Install Node.js 22+ and run:

```bash
python run_demo.py
```

Open **http://127.0.0.1:3000/** and the dashboard on port 8000. The launcher enables the explicit strict demonstration policy and generates a fresh shared acknowledgement key. Benign requests reach a harmless counter handler (200); blocked requests (403) and review requests (409) do not. Scanner outages deny with 503. Invalid scan input returns 422.

Set `PRAHARI_MODE=monitor` before launching to let requests reach the handler while recording advisory decisions. Acknowledgement events are authenticated, action-validated, and idempotent. They are trusted adapter reports. There is no production proxy, durable acknowledgement retry queue, or claim of network interception.

## Configuration

See `.env.example` for process environment variables; it is a reference file and is **not automatically loaded**. Defaults work without configuration.

| Variable | Default | Purpose |
| --- | --- | --- |
| PRAHARI_DB | data/prahari.db | Persistent SQLite location |
| PRAHARI_MODELS_DIR | models/ | Trusted model directory |
| PRAHARI_POLICY | review-first | review-first or demo-strict |
| PRAHARI_REVIEW_THRESHOLD | 30 | Review threshold from 1 to 90 |
| PRAHARI_INTEGRATION_KEY | unset | Required only for acknowledgement writes |
| PRAHARI_MODE | enforce | Optional Node adapter enforce / monitor mode |
| PRAHARI_URL | http://127.0.0.1:8000 | Scanner URL when Node is launched separately |
| DEMO_PORT | 3000 | Optional Node adapter port |

Windows PowerShell: `$env:PRAHARI_POLICY = "demo-strict"`. Bash: `export PRAHARI_POLICY=demo-strict`. Restart the process after changing configuration. `run_demo.py` always uses the local scanner on port 8000.

## Verify and train

```bash
python -m unittest discover -s tests -v
node --check prahari/static/app.js
node --check demo-app/server.mjs
python scripts/check_integration.py
```

The live integration check uses temporary SQLite storage and ports 8129/3139. Node is required for that check only. See `docs/verification.txt` for the latest verification and limits.

Rebuild the illustrative request classifier with `python -m scripts.train_request`. Its 100 synthetic examples are bundled in `scripts/training_data.py`. This is a reproducible development baseline, not independent evaluation. The recovered phishing artifact is included with its original feature schema and provenance; its original training dataset and training pipeline are not in this repository. See `docs/models.md`.

## Data and operating scope

Scans never fetch websites or execute supplied payloads. History stores analysis metadata, numeric scores, generic findings, and offsets; it does not store original input, credential values, hostnames, or matched excerpts. Copy `data/prahari.db` after stopping the server to retain history. Databases, environment files, caches, and virtual environments are ignored by git.

This is a loopback-bound single-user foundation. The workspace API has no user authentication, and trusted-host checks restrict accepted local hostnames. Shared/public deployment requires authentication, authorization, retention controls, and independent model evaluation. Only load trusted model files: joblib serialization can execute code; manifest hashes check integrity, not publisher authenticity.

Current architecture: `docs/architecture.md`. API reference: `docs/api.md` and `/docs`. Earlier milestone notes and the original roadmap are retained under `docs/history/` as historical context.

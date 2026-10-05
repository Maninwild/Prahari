# Prahari — Milestone 1

A unified, local web threat analysis backend combining the authors' PhiUSIIL phishing detector and SentinelAI request detector. This package implements the shared detection core and API, the first step of the agreed roadmap.

## Start on Windows

1. Install Python 3.12 if it is not already installed (`py -3.12 --version`).
2. Extract this ZIP to a convenient folder, for example `D:\private\Prahari`.
3. Open the folder containing this README and double-click `run_windows.bat`.
4. Wait for the first dependency installation. Open http://127.0.0.1:8000/docs.
5. Expand `POST /api/v1/scans`, click **Try it out**, paste a sample below, and click **Execute**.
6. Press Ctrl+C in the server terminal to stop.

The API documentation is the milestone's testing interface. The Angular dashboard is a later milestone. This local service has no authentication; keep its default loopback binding.

Manual PowerShell setup, from the project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn prahari.api:app --host 127.0.0.1 --port 8000 --no-access-log
```

If port 8000 is occupied, use `--port 8001` and open that port instead. On Linux/macOS, use Python 3.12, `python3.12 -m venv .venv`, and `.venv/bin/python` for the equivalent commands. The Windows launcher is supplied but has not been executed on Windows in this development session.

## Try these scans

Ordinary request (Allow with the packaged models):

```json
{"input_type":"http_request","content":"GET /products?page=2 HTTP/1.1"}
```

Phishing baseline (Review; the old model remains experimental):

```json
{"input_type":"url","content":"https://github.com/openai"}
```

SQL injection indicators:

```json
{"input_type":"payload","content":"' OR 1=1--"}
```

JSON XSS indicators:

```json
{"input_type":"payload","content_type":"application/json","content":"{\"comment\":\"<script>alert(1)</script>\"}"}
```

Command injection indicators:

```json
{"input_type":"payload","content":"localhost;whoami"}
```

Multiple categories and double-encoded traversal:

```json
{"input_type":"http_request","content":"GET /?file=%252e%252e%252fetc/passwd&x=%3Cscript%3E HTTP/1.1"}
```

These strings are inspected locally, never sent to a target or executed. Full HTTP inputs need a valid request line, percent-encoded spaces in the target, headers on separate lines and a blank line before a body. Older shorthand such as `POST /login username=...` should be submitted as a payload instead.

## What is implemented

- One validated input and output contract for URLs, HTTP request text and payloads.
- One orchestrator with phishing ML, request ML and multi-category rules.
- Component-aware views; repeated query keys retained and JSON plus signs preserved.
- Stable rule IDs, component locations and matched offsets, with model signals kept separate.
- One category-score map and provisional max-based risk index.
- Review on unsupported analysis, missing models, weak predictions and legacy phishing results.
- Loaded, hash-checked model bundles; request model trained offline, not at every server startup.
- Health, readiness and interactive OpenAPI documentation.
- 64 KiB API body limit, 10,000 input-character limit, bounded field/JSON handling.
- No original payload or matched text is returned; findings contain generic rule descriptions and offsets. No scan history or application logging is enabled in this milestone.

## Decisions and limits

The default policy is review-first. It can Allow low-scoring supported requests or request Review. No ML model in this release is validated for automatic blocking. Scores are experimental policy indices, not accuracy, exploitability, or calibrated maliciousness probabilities.

For a local demonstration of the Block decision, explicitly enable the server-side demo policy before launching:

```powershell
$env:PRAHARI_POLICY = "demo-strict"
.\.venv\Scripts\python.exe -m uvicorn prahari.api:app --host 127.0.0.1 --port 8000 --no-access-log
```

This profile returns Block for the destructive-SQL, script-element and traversal signatures. It is deliberately not the default: quoted code or legitimate relative paths can trigger these rules. Stop the server and run `Remove-Item Env:PRAHARI_POLICY` to return to the default. Client requests cannot select a policy. In both profiles `action_taken` is always `none`. No traffic has been intercepted or blocked by this release.

The phishing forest still uses its original 22-feature definition, including the previously identified hostname/shortener shortcomings. Its weights and feature meaning must change together during retraining. URL validation is improved outside that baseline, but validation does not repair the old model. Every successful phishing scan is Review, including low scores. The request model is refitted from the original 100 synthetic examples using shared component views; performance is not measured on independent traffic. ML outputs describe the aggregate components, while rules localize evidence per component.

The parser supports HTTP origin-form targets, JSON, form-encoded and plain-text bodies. Multipart, compressed, chunked or ambiguous bodies force incomplete analysis and Review. JSON strings receive a raw view and a heuristic Unicode/entity view; this does not simulate every application's execution semantics. No live URL fetching, external-link extraction from request bodies, persistent history, authentication, frontend dashboard or integration enforcement is included yet. None of these are claimed complete.

## Checks and reproducibility

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The 15 tests cover detector families, combined indicators, decoding, literal plus signs, duplicate parameters, malformed input, model failures, privacy of output, policy separation and API behavior. They are regression tests, not an accuracy benchmark.

To rebuild the request baseline and artifact manifest:

```powershell
.\.venv\Scripts\python.exe -m scripts.train_request
```

Only load the bundled or independently trusted model files: joblib files are executable serialization, and a hash in a locally supplied manifest is an integrity check, not a signature. The manifest records the build environment and hashes. Key dependencies are pinned; transitive dependencies are resolved by pip. Do not edit the legacy phishing feature schema without training a corresponding replacement model.

## Code map

| Path | Role |
|---|---|
| `prahari/schemas.py` | Public input/result contract |
| `prahari/parsing.py` | Components and bounded inspection views |
| `prahari/detectors/` | Rules and versioned model adapters |
| `prahari/policy.py` | Review-first and explicit demo policy |
| `prahari/engine.py` | Unified orchestration |
| `prahari/api.py` | FastAPI endpoints |
| `models/` | Two runnable baseline models and manifest |
| `scripts/train_request.py` | Offline baseline rebuild |
| `tests/test_core.py` | Functional regression suite |
| `docs/openapi.json` | Generated API specification |

Original project contributions belong to Manjunath Padgetwar and the collaborator who co-created the supplied projects. The collaborator's name has not been supplied. No third-party ownership or new license is asserted here.

## Next milestone

Repair phishing features and data coverage, establish independent evaluation, and promote a replacement only after it passes the agreed gates. Continue with persistent APIs, Angular workspace and the Node.js protection integration in the roadmap. This milestone is intended for local development, not public deployment.

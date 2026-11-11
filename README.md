# Prahari

A unified web threat analysis, session monitoring and network behaviour prototype. Prahari combines phishing URL classification, SQL injection, XSS, command injection and path traversal analysis in one API, workspace, policy and history store.

**Start here:** Python 3.12 + Node.js 22 or newer → extract the project → double-click `run_protected_demo.bat` → open http://127.0.0.1:3000/ and http://127.0.0.1:8000/.

## Session and network upgrade

Version 2 adds authenticated session telemetry, seven behavioural rules, experimental Isolation Forest models, Zeek connection-log replay/follow, correlated incidents, triage and evidence export. Start with [the upgrade guide](docs/SECURENET_UPGRADE.md). The original request protection remains integrated.

On the demo board, click **Simulate 5 failed logins**, then inspect the incident in the workspace. The anomaly models use synthetic demonstration data; real-network performance is not yet established.

## What works

- One scan composer accepts an absolute HTTP(S) URL, complete HTTP request or payload.
- A v2 phishing forest uses 18 corrected lexical features and domain-separated evaluation.
- Request classification uses TF-IDF character features and Logistic Regression; explicit rules preserve multiple attack categories.
- Separate model estimates, rule matches, component locations, risk scores and decision reasons.
- Persistent history, scan-ID search, decision filters, JSON exports and analyst labels.
- Review-first and Protect policies, saved across restarts.
- A protected Node community board: allowed submissions publish; Block and Review never reach its handler.
- Authenticated enforcement acknowledgements, retry deduplication and a durable Node outbox.
- Optional workspace bearer authentication, same-origin write checks, Host validation, scan rate limiting and bounded input.

This release is a usable local single-user product. It does not claim production-WAF coverage, live URL reputation, multi-tenant isolation or independently measured real-world accuracy.

## Windows setup

1. Stop any earlier Prahari terminal using Ctrl+C.
2. Extract into a new folder such as `D:\private\Prahari`.
3. Verify `py -3.12 --version` and `node --version` (Node 22+).
4. Double-click `run_protected_demo.bat`. Initial dependency installation needs internet access. Later scans are offline.
5. Open the board at http://127.0.0.1:3000/ and workspace at http://127.0.0.1:8000/.
6. Keep the terminal open; Ctrl+C stops both services.

The launcher checks ports and models and supplies an ephemeral integration key to both services. It uses the Protect policy unless an existing saved policy overrides it; use the workspace policy selector to change it. The Windows launchers have been reviewed but not executed on Windows in this environment.

To run just the workspace, use `run_windows.bat`. This uses Review-first unless a policy is already saved. API documentation: http://127.0.0.1:8000/docs.

Manual PowerShell setup:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run_demo.py
```

Linux/macOS: create a Python 3.12 virtual environment, install requirements, then run `python run_demo.py`. No npm dependencies are needed for the application.

## Demonstrate the complete workflow

1. Select **Benign** in the board and submit. HTTP 200 publishes the content and increments `handler_reached`.
2. Select **Block example** and submit. With Protect enabled, HTTP 403 denies it and the counter does not increase.
3. Select **Review example** and submit. HTTP 409 holds it; it is not published or automatically queued for later replay.
4. Open the workspace. The acknowledged-block counter reflects adapter reports, separate from scanner recommendations. It refreshes every ten seconds.
5. Reopen a scan from history. Inspect category scores, evidence, model estimates and any acknowledged action. Record an analyst verdict. Verdicts are annotations, not automatic retraining, exceptions or replay instructions.
6. Switch to Review-first to assess unfamiliar content without generating scanner Block decisions. In enforce mode, Review is still denied. Use Node monitor mode when you want requests to proceed during evaluation.

Every sample is treated as text. The board contains no intentionally vulnerable SQL query or shell call. The protection gate demonstrably prevents the application handler from running; it does not demonstrate a successful exploit.

## Policy and integration

The unified risk index is the maximum applicable category score. Rule scores and ML probabilities remain separate evidence. Current constants are provisional: risk ≥30 or weak/ambiguous ML triggers Review; low supported scores can Allow. Protect enables selected SQL comparison, destructive SQL, script, shell and traversal rules to return Block. ML alone never authorizes Block.

`demo-app/prahari-client.mjs` exports `PrahariClient`. Call `inspect({input_type,content,content_type})`, check the returned action **before** application work, then call `acknowledge(scan,action)` after the actual disposition. The example server is the integration reference. Do not rely on a browser-side check to protect a backend.

Environment variables:

| Variable | Use |
|---|---|
| `PRAHARI_DB` | Scanner database path; default `data/prahari.db` |
| `PRAHARI_API_KEY` | Optional workspace bearer key; enter it in the workspace key field |
| `PRAHARI_INTEGRATION_KEY` | Shared key for adapter/API communication; launcher creates it |
| `PRAHARI_POLICY` | `demo-strict` enables Protect on first start; persisted UI setting takes precedence |
| `PRAHARI_MODE` | Node `enforce` (default) or `monitor` |
| `PRAHARI_URL` | Adapter's scanner base URL |
| `PRAHARI_PSEUDONYM_KEY` | Stable shared HMAC key for session and network actor correlation; launcher saves a local default |
| `PRAHARI_DEMO_DATA` | Board and outbox directory |
| `PRAHARI_ALLOWED_HOSTS` | Comma-separated allowed API hosts |

Enforce: Allow publishes, Block returns 403, Review returns 409. Monitor: all successfully analysed inputs proceed, while recommendations are recorded. Scanner errors or the five-second timeout deny with 503 in both modes. Outages are not labelled attacks. Acknowledgements retry from a local outbox; permanent rejection needs operator investigation. The outbox records only event metadata. A process crash between application action and outbox persistence can still leave an unacknowledged action; this is not an exactly-once distributed transaction.

## Data and privacy

Scanner history stores numeric model signals, generic rule descriptions, offsets, decisions and versions. Matched excerpts appear only in the immediate response and are removed before persistence. Original scan inputs are not stored. The board separately stores the latest 100 **accepted** submissions as application content and displays them with textContent. Do not paste secrets into the demonstration board.

Both services bind to loopback by default. The workspace key is optional for local use; when enabled it protects all `/api/` routes. The shared integration key also authorizes trusted adapter access. This is one trust domain, not per-user or per-project isolation. Use TLS and a deployment-specific access policy before exposing it beyond localhost. Same-origin and rate-limit controls are complementary safeguards, not substitutes for authentication.

Move the stopped application's entire `data` directory to retain history, board content and outbox. No runtime databases or secrets are included in this package. Delete that directory only if you intentionally want a fresh local installation.

## Evaluation

See `evaluation/phishing_training.json`, `evaluation/request_diagnostics.json`, and `docs/EVALUATION.md`.

The v2 model used 40,000 original training rows plus 20,000 generated benign URL variants. Calibration used a separate group of domains. An 8,000-original-row held-out sample achieved 98.625% accuracy, with 13 false positives and 97 false negatives. This is one-source evaluation; it does not establish real-traffic performance. The 26 authored request diagnostics include training-like regressions and context-dependent benign code. Protect flagged all 16 attack examples, but also blocked two benign examples. Review-first is appropriate while learning a new workload.

Models are bundled and do not train at startup. Only load trusted model artifacts. Hashes detect unintended changes; they are not publisher signatures.

## Reproduce checks and training

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts/check_integration.py
.\.venv\Scripts\python.exe -m scripts.evaluate_release
.\.venv\Scripts\python.exe -m scripts.train_phishing --dataset "PATH\PhiUSIIL_Phishing_URL_Dataset.csv"
.\.venv\Scripts\python.exe -m scripts.train_request
```

Training data is not required to run the product. Obtain the original PhiUSIIL CSV from UCI dataset 967 or use your supplied original archive. The request examples are bundled. Training scripts must run from the project folder. Domain grouping uses the packaged public-suffix snapshot without network requests.

## Docker

Set `PRAHARI_API_KEY`, `PRAHARI_INTEGRATION_KEY` and `PRAHARI_PSEUDONYM_KEY` to different private random values, then run `docker compose up --build`. Open the same local ports and enter the workspace key in the UI. Ports are published to localhost only and data uses named volumes. Docker files are provided, but container execution was not verified in the build environment.

## Submission package

`submission/` retains the v1 ten-slide deck, captioned demo video, narration script and project description. The new SecureNet concept-note draft and incident screenshot cover the upgrade. `docs/` covers architecture, evaluation, security and repository publishing. GitHub Actions checks are included. Repository: https://github.com/Maninwild/Prahari. The SecureNet v2 release is available on the securenet-v2 branch for review alongside the existing main branch. No competition submission is claimed.

Original projects were created by Manjunath Padgetwar and his collaborator. The collaborator's name was not provided. Dataset attribution appears in `NOTICE.md`; do not attribute all source data to the project team.
